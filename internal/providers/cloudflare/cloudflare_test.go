package cloudflare

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestProviderApply(t *testing.T) {
	t.Parallel()

	t.Run("apply retries discover owned IPv6 block and release only that block", func(t *testing.T) {
		t.Parallel()

		d := model.Decision{
			ID:    "decision-one",
			IP:    "2001:db8::1",
			State: model.DecisionBanned,
		}
		var rules = []rule{{
			ID:            "foreign",
			Mode:          "block",
			Notes:         "manual",
			Configuration: filter{"ip6", d.IP},
		}}
		var created, deleted int
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			switch r.Method {
			case http.MethodGet:
				assert.Equal(t, d.IP, r.URL.Query().Get("configuration.value"))
				mu.Lock()
				result := append([]rule(nil), rules...)
				mu.Unlock()

				assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result}))
			case http.MethodPost:
				var block rule
				if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
					assert.NoError(t, err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				assert.Equal(t, "ip6", block.Configuration.Target)
				assert.Equal(t, "warden:decision-one", block.Notes)
				block.ID = "owned"
				mu.Lock()
				rules = append(rules, block)
				created++
				mu.Unlock()
				w.Write([]byte(`{"success":true}`)) // nolint:errcheck
			case http.MethodDelete:
				assert.Equal(t, "/rules/owned", r.URL.Path)
				mu.Lock()
				rules = rules[:1]
				deleted++
				mu.Unlock()
				w.Write([]byte(`{"success":true}`)) // nolint:errcheck
			}
		}))
		defer server.Close()

		p := Provider{
			RulesURL: server.URL + "/rules",
			Client:   server.Client(),
			Token:    "secret",
		}

		require.NoError(t, p.Deliver(t.Context(), d))
		require.NoError(t, p.Deliver(t.Context(), d))
		d.State = model.DecisionUnbanned

		require.NoError(t, p.Deliver(t.Context(), d))
		require.NoError(t, p.Deliver(t.Context(), d))
		mu.Lock()
		defer mu.Unlock()

		assert.Equal(t, 1, created)
		assert.Equal(t, 1, deleted)
		assert.Len(t, rules, 1)
	})

	t.Run("rejects unknown desired state before calling Cloudflare", func(t *testing.T) {
		t.Parallel()

		p := Provider{}
		require.ErrorContains(t, p.Deliver(t.Context(), model.Decision{IP: "203.0.113.1"}), "invalid decision state")
	})

	t.Run("forbidden response includes the numeric Cloudflare code", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"private detail"}]}`))
		}))
		defer server.Close()
		p := Provider{RulesURL: server.URL, Client: server.Client()}
		require.EqualError(t, p.Deliver(t.Context(), model.Decision{IP: "203.0.113.1", State: model.DecisionBanned}), "Cloudflare HTTP 403 (code 10000)")
	})

	t.Run("API failure is retryable", func(t *testing.T) {
		t.Parallel()

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
		defer s.Close()
		p := Provider{
			RulesURL: s.URL,
			Client:   s.Client(),
			Token:    "secret",
		}

		require.ErrorContains(t, p.Deliver(t.Context(), model.Decision{IP: "203.0.113.1", State: model.DecisionBanned}), "429")
	})
}

// callResponse sends a request to a mock Cloudflare API returning the given response body.
func callResponse(t *testing.T, body string) error {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	provider := Provider{
		RulesURL: server.URL,
		Client:   server.Client(),
	}
	_, err := provider.call(t.Context(), http.MethodGet, server.URL, nil)
	return err
}

func TestResponseValidation(t *testing.T) {
	t.Parallel()

	t.Run("accepts one JSON document", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, `{"success":true,"result":[]}`)
		require.NoError(t, err)
	})

	t.Run("accepts JSON whitespace", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, "{\"success\":true} \n\t")
		require.NoError(t, err)
	})

	t.Run("rejects trailing JSON document", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, `{"success":true}{"success":true}`)
		require.ErrorContains(t, err, "decode Cloudflare response")
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, `{"success":true`)
		require.ErrorContains(t, err, "decode Cloudflare response")
	})

	t.Run("rejects oversized body even if the excess is whitespace", func(t *testing.T) {
		t.Parallel()

		body := `{"success":true}` + strings.Repeat(" ", maxResponseBytes)
		err := callResponse(t, body)
		require.ErrorContains(t, err, "Cloudflare response exceeds")
	})
}

func TestFindPagination(t *testing.T) {
	t.Parallel()

	want := rule{
		Mode:          "block",
		Notes:         "warden:one",
		Configuration: filter{Target: "ip", Value: "203.0.113.5"},
	}

	t.Run("reads all pages and only returns exactly owned rules", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			assert.Equal(t, want.Notes, r.URL.Query().Get("notes"))
			assert.Equal(t, want.Configuration.Value, r.URL.Query().Get("configuration.value"))
			var result []rule
			switch r.URL.Query().Get("page") {
			case "1":
				result = []rule{
					{
						ID:            "foreign",
						Mode:          "block",
						Notes:         "not-warden",
						Configuration: want.Configuration,
					},
					{
						ID:            "owned-one",
						Mode:          want.Mode,
						Notes:         want.Notes,
						Configuration: want.Configuration,
					},
				}
			case "2":
				result = []rule{{
					ID:            "owned-two",
					Mode:          want.Mode,
					Notes:         want.Notes,
					Configuration: want.Configuration,
				}}
			default:
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"success": true, "result": result, "result_info": map[string]int{"total_pages": 2},
			}))
		}))
		defer server.Close()

		ids, err := (Provider{RulesURL: server.URL, Client: server.Client()}).find(t.Context(), want)
		require.NoError(t, err)
		assert.Equal(t, []string{"owned-one", "owned-two"}, ids)
		assert.EqualValues(t, 2, requests.Load())
	})

	t.Run("rejects excessive page count without further requests", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"total_pages":101}}`))
		}))
		defer server.Close()

		ids, err := (Provider{RulesURL: server.URL, Client: server.Client()}).find(t.Context(), want)
		require.ErrorContains(t, err, "pagination exceeds supported bounds")
		assert.Nil(t, ids)
		assert.EqualValues(t, 1, requests.Load())
	})

	t.Run("rejects negative page count", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"total_pages":-1}}`))
		}))
		defer server.Close()

		_, err := (Provider{RulesURL: server.URL, Client: server.Client()}).find(t.Context(), want)
		require.ErrorContains(t, err, "pagination exceeds supported bounds")
	})

	t.Run("propagates second page failure", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("page") == "2" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"total_pages":2}}`))
		}))
		defer server.Close()

		_, err := (Provider{RulesURL: server.URL, Client: server.Client()}).find(t.Context(), want)
		require.ErrorContains(t, err, "Cloudflare HTTP 502")
	})

	t.Run("allows absent pagination metadata on a single-page response", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		}))
		defer server.Close()

		ids, err := (Provider{RulesURL: server.URL, Client: server.Client()}).find(t.Context(), want)
		require.NoError(t, err)
		assert.Empty(t, ids)
		assert.EqualValues(t, 1, requests.Load())
	})
}
