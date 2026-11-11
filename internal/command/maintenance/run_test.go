package maintenance

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	housekeeping "github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("status retrieves the scheduler snapshot", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/maintenance", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"prune":{"running":false},"optimize":{},"pruneInterval":"1h0m0s","optimizeInterval":"24h0m0s"}`))
		}))
		defer server.Close()

		var value housekeeping.Status

		require.NoError(t, Run(t.Context(), server.URL, "admin-secret", ActionStatus, func(result any) error {
			var ok bool
			value, ok = result.(housekeeping.Status)
			require.True(t, ok)
			return nil
		}))
		assert.Equal(t, "1h0m0s", value.PruneInterval)
		assert.Equal(t, "24h0m0s", value.OptimizeInterval)
	})

	t.Run("prune invokes only the observation cleanup endpoint", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/maintenance/prune", r.URL.Path)
			assert.Empty(t, r.Header.Get("Content-Type"))
			_, _ = w.Write([]byte(`{"prune":{"lastSuccessAt":"2026-11-11T16:00:00Z"},"optimize":{},"pruneInterval":"1h0m0s","optimizeInterval":"24h0m0s"}`))
		}))
		defer server.Close()

		var outputBuffer bytes.Buffer
		format := output.FormatJSON

		require.NoError(t, Run(t.Context(), server.URL, "admin-secret", ActionPrune, output.New(&format, &outputBuffer)))
		assert.Contains(t, outputBuffer.String(), `"lastSuccessAt": "2026-11-11T16:00:00Z"`)
	})

	t.Run("optimize invokes only SQLite planner maintenance", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/maintenance/optimize", r.URL.Path)
			_, _ = w.Write([]byte(`{"prune":{},"optimize":{},"pruneInterval":"1h0m0s","optimizeInterval":"24h0m0s"}`))
		}))
		defer server.Close()

		var outputBuffer bytes.Buffer
		format := output.FormatYAML

		require.NoError(t, Run(t.Context(), server.URL, "admin-secret", ActionOptimize, output.New(&format, &outputBuffer)))
		assert.Contains(t, outputBuffer.String(), "pruneInterval:")
		assert.Contains(t, outputBuffer.String(), "optimizeInterval:")
	})

	t.Run("requires a token before contacting Warden", func(t *testing.T) {
		t.Parallel()

		called := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", ActionStatus, func(any) error {
			called = true
			return nil
		})

		require.ErrorContains(t, err, "admin-token")
		assert.False(t, called)
	})

	t.Run("propagates HTTP conflict without printing a success status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"database maintenance already running"}`))
		}))
		defer server.Close()

		encoded := false
		err := Run(t.Context(), server.URL, "admin-secret", ActionOptimize, func(any) error {
			encoded = true
			return nil
		})

		require.ErrorContains(t, err, "409")
		assert.False(t, encoded)
	})

	t.Run("returns encoding errors", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"prune":{},"optimize":{},"pruneInterval":"1h0m0s","optimizeInterval":"24h0m0s"}`))
		}))
		defer server.Close()

		writeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin-secret", ActionStatus, func(any) error { return writeErr })

		require.ErrorIs(t, err, writeErr)
	})

	t.Run("rejects unsupported operations without contacting Warden", func(t *testing.T) {
		t.Parallel()

		err := Run(t.Context(), "http://127.0.0.1:8080", "admin-secret", "vacuum", func(any) error {
			t.Fatal("must not encode an unsupported operation")
			return nil
		})

		require.ErrorContains(t, err, "unsupported maintenance action")
	})

	t.Run("propagates canceled context", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := Run(ctx, "http://127.0.0.1:8080", "admin-secret", ActionStatus, func(any) error {
			t.Fatal("must not encode canceled request")
			return nil
		})

		require.ErrorIs(t, err, context.Canceled)
	})
}
