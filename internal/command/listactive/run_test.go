package listactive

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("lists active bans using the authenticated application API", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/warden/bans", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[{"decision":{"id":"id-one"},"sources":[],"deliveries":[]}]`))
		}))
		defer server.Close()

		var records []client.Record
		err := Run(t.Context(), server.URL+"/warden", "admin-secret", func(value any) error {
			var ok bool
			records, ok = value.([]client.Record)
			require.True(t, ok)
			return nil
		})

		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Equal(t, "id-one", records[0].Decision.ID)
	})

	t.Run("does not encode unsuccessful API responses", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		encoded := false
		err := Run(t.Context(), server.URL, "wrong-token", func(any) error {
			encoded = true
			return nil
		})

		require.ErrorContains(t, err, "application HTTP 401")
		assert.False(t, encoded)
	})

	t.Run("propagates output encoding failures", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		}))
		defer server.Close()

		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin-secret", func(any) error {
			return encodeErr
		})

		require.ErrorIs(t, err, encodeErr)
	})
}

func TestRunClientValidation(t *testing.T) {
	t.Parallel()

	t.Run("requires token", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("rejects insecure remote URL", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://warden.example.com", "admin", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "HTTPS")
		assert.False(t, encoded)
	})

	t.Run("canceled HTTP request does not encode", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		encoded := false
		err := Run(ctx, "http://127.0.0.1:8080", "admin", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.False(t, encoded)
	})
}
