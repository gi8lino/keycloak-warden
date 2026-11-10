package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestProviderApply(t *testing.T) {
	t.Parallel()

	t.Run("sends configured headers and desired revision", func(t *testing.T) {
		t.Parallel()
		want := decisions.Decision{
			ID: "stable", IP: "203.0.113.2", Revision: 3, State: decisions.StateUnbanned, ExpiresAt: time.Now().UTC(),
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
			assert.Equal(t, "warden", r.Header.Get("X-Source"))
			assert.Empty(t, r.Header.Get("X-Warden-Signature"))
			assert.Empty(t, r.Header.Get("X-Warden-Timestamp"))
			var got decisions.Decision
			assert.NoError(t, json.Unmarshal(body, &got))
			assert.Equal(t, want, got)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		p := Provider{URL: server.URL, Headers: http.Header{"Authorization": {"Bearer token"}, "X-Source": {"warden"}}, Client: server.Client()}
		require.NoError(t, p.Apply(t.Context(), want))
	})

	t.Run("works without headers", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		p := Provider{URL: server.URL, Client: server.Client()}
		require.NoError(t, p.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}))
	})

	t.Run("rejects unknown desired state before sending webhook", func(t *testing.T) {
		t.Parallel()
		p := Provider{}
		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{}), "invalid decision state")
	})

	t.Run("non-success response propagates to dispatcher", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
		defer server.Close()
		p := Provider{URL: server.URL, Client: server.Client()}
		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}), "503")
	})
}
