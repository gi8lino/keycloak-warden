package unban

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/output"
)

func TestRunFailures(t *testing.T) {
	t.Parallel()

	t.Run("invalid IP fails before connecting", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "admin", []string{"bad-ip"}, func(any) error {
			encoded = true
			return nil
		})
		require.Error(t, err)
		assert.False(t, encoded)
	})

	t.Run("missing token fails before connecting", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", []string{"203.0.113.10"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("list failure does not encode results", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		encoded := false
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "list active bans")
		assert.ErrorContains(t, err, "503")
		assert.False(t, encoded)
	})

	t.Run("encoding failure propagates after successful release", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`[{"decision":{"id":"one","ipAddress":"203.0.113.10"}}]`))
				return
			}
			_, _ = w.Write([]byte(`{"decision":{"id":"one","state":"unbanned"}}`))
		}))
		defer server.Close()
		encodeErr := errors.New("cannot write output")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Succeeded)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
	})

	t.Run("joins missing decision and encoding failures", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		}))
		defer server.Close()
		encodeErr := errors.New("cannot write output")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Failed)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
		assert.ErrorContains(t, err, "active ban not found")
	})
}
