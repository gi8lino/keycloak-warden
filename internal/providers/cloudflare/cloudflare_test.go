package cloudflare

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestProviderApply(t *testing.T) {
	t.Parallel()

	t.Run("apply retries discover owned IPv6 block and release only that block", func(t *testing.T) {
		t.Parallel()

		d := decisions.Decision{ID: "decision-one", IP: "2001:db8::1", Active: true}
		var rules = []rule{{ID: "foreign", Mode: "block", Notes: "manual", Configuration: filter{"ip6", d.IP}}}
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

		p := Provider{RulesURL: server.URL + "/rules", Client: server.Client(), Token: "secret"}

		require.NoError(t, p.Apply(t.Context(), d))
		require.NoError(t, p.Apply(t.Context(), d))
		d.Active = false

		require.NoError(t, p.Apply(t.Context(), d))
		require.NoError(t, p.Apply(t.Context(), d))
		mu.Lock()
		defer mu.Unlock()

		assert.Equal(t, 1, created)
		assert.Equal(t, 1, deleted)
		assert.Len(t, rules, 1)
	})

	t.Run("forbidden response includes the numeric Cloudflare code", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"private detail"}]}`))
		}))
		defer server.Close()
		p := Provider{RulesURL: server.URL, Client: server.Client()}
		require.EqualError(t, p.Apply(t.Context(), decisions.Decision{IP: "203.0.113.1"}), "Cloudflare HTTP 403 (code 10000)")
	})

	t.Run("API failure is retryable", func(t *testing.T) {
		t.Parallel()

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
		defer s.Close()
		p := Provider{RulesURL: s.URL, Client: s.Client(), Token: "secret"}

		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{IP: "203.0.113.1"}), "429")
	})
}
