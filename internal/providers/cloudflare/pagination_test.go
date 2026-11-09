package cloudflare

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindPagination(t *testing.T) {
	t.Parallel()

	want := rule{Mode: "block", Notes: "warden:one", Configuration: filter{Target: "ip", Value: "203.0.113.5"}}

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
					{ID: "foreign", Mode: "block", Notes: "not-warden", Configuration: want.Configuration},
					{ID: "owned-one", Mode: want.Mode, Notes: want.Notes, Configuration: want.Configuration},
				}
			case "2":
				result = []rule{{ID: "owned-two", Mode: want.Mode, Notes: want.Notes, Configuration: want.Configuration}}
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
