package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// TestWorkerStatus verifies the public admin client's worker endpoint contract.
func TestWorkerStatus(t *testing.T) {
	t.Parallel()

	t.Run("decodes workers and respects route prefix", func(t *testing.T) {
		t.Parallel()

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/warden/workers", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"actions":{"state":"idle","startedAt":"2026-11-25T08:00:00Z","pendingDeliveries":3},"maintenance":{"state":"processing","startedAt":"2026-11-25T08:00:00Z"}}`))
		}))
		defer upstream.Close()

		api, err := New(upstream.URL+"/warden", "token")
		require.NoError(t, err)
		workers, err := api.WorkerStatus(context.Background())

		require.NoError(t, err)
		assert.Equal(t, workerstate.StateIdle, workers.Actions.State)
		assert.Equal(t, 3, workers.Actions.PendingDeliveries)
		assert.Equal(t, workerstate.StateProcessing, workers.Maintenance.State)
	})

	t.Run("propagates HTTP error without a fabricated status", func(t *testing.T) {
		t.Parallel()

		upstream := httptest.NewServer(http.NotFoundHandler())
		defer upstream.Close()

		api, err := New(upstream.URL, "token")
		require.NoError(t, err)
		workers, err := api.WorkerStatus(t.Context())

		require.Error(t, err)
		assert.Empty(t, workers.Actions.State)
	})
}
