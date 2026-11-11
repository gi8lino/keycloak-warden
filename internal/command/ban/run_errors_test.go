package ban

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/output"
)

func TestRunFailures(t *testing.T) {
	t.Parallel()

	t.Run("invalid IP prevents API access and encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "admin", []string{"invalid-ip"}, time.Hour, "reason", func(any) error {
			encoded = true
			return nil
		})
		require.Error(t, err)
		assert.False(t, encoded)
	})

	t.Run("missing token fails before encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", []string{"203.0.113.10"}, time.Hour, "reason", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("encoding failure is returned after successful API call", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"decision":{"id":"one"}}`))
		}))
		defer server.Close()
		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, time.Hour, "reason", func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Succeeded)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
	})

	t.Run("joins request and encoding failures", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer server.Close()
		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, time.Hour, "reason", func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Failed)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
		assert.ErrorContains(t, err, "failed 203.0.113.10")
		assert.ErrorContains(t, err, "502")
	})

	t.Run("cancellation still reports a partial empty batch", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var batch output.Batch
		err := Run(ctx, "http://127.0.0.1:8080", "admin", []string{"203.0.113.10"}, time.Hour, "reason", func(value any) error {
			batch = value.(output.Batch)
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, "ban", batch.Operation)
		assert.Empty(t, batch.Results)
	})
}
