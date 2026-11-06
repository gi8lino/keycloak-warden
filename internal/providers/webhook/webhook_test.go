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
	"github.com/gi8lino/keycloak-warden/internal/signing"
)

func TestProviderApply(t *testing.T) {
	t.Parallel()

	t.Run("signs each desired revision", func(t *testing.T) {
		t.Parallel()

		want := decisions.Decision{
			ID:        "stable",
			IP:        "203.0.113.2",
			Revision:  3,
			Active:    false,
			ExpiresAt: time.Now().UTC(),
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			assert.True(t, signing.Valid("key", r.Header.Get("X-Warden-Timestamp"), r.Header.Get("X-Warden-Signature"), body, time.Now()))
			var got decisions.Decision

			assert.NoError(t, json.Unmarshal(body, &got))
			assert.Equal(t, want, got)
			w.WriteHeader(204)
		}))
		defer server.Close()
		p := Provider{URL: server.URL, Secret: "key", Client: server.Client()}

		require.NoError(t, p.Apply(t.Context(), want))
	})

	t.Run("non-success response propagates to dispatcher", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
		defer server.Close()
		p := Provider{URL: server.URL, Secret: "key", Client: server.Client()}

		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{}), "503")
	})
}
