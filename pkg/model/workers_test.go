package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkersJSON(t *testing.T) {
	t.Parallel()

	t.Run("decodes existing flat worker responses", func(t *testing.T) {
		t.Parallel()

		var workers Workers
		data := []byte(`{"enforcement":{"state":"idle","startedAt":"2026-11-25T08:00:00Z","pendingDeliveries":3,"activeBans":2},"maintenance":{"state":"processing","startedAt":"2026-11-25T08:00:00Z","prune":{"running":true},"pruneInterval":"1h0m0s"}}`)
		require.NoError(t, json.Unmarshal(data, &workers))

		assert.Equal(t, WorkerIdle, workers.Enforcement.State)
		assert.Equal(t, 3, workers.Enforcement.PendingDeliveries)
		assert.Equal(t, 2, workers.Enforcement.ActiveBans)

		assert.Equal(t, WorkerProcessing, workers.Maintenance.State)
		assert.True(t, workers.Maintenance.Prune.Running)
		assert.Equal(t, "1h0m0s", workers.Maintenance.PruneInterval)
	})

	t.Run("encodes embedded action fields at the top level", func(t *testing.T) {
		t.Parallel()

		worker := EnforcementWorker{
			RuntimeStatus: RuntimeStatus{
				State:     WorkerIdle,
				StartedAt: time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC),
			},
			QueueStats: QueueStats{
				PendingDeliveries: 3,
				ActiveBans:        2,
			},
		}

		encoded, err := json.Marshal(worker)
		require.NoError(t, err)

		const want = `{"state":"idle","startedAt":"2026-11-25T08:00:00Z","pendingDeliveries":3,"retryingDeliveries":0,"exhaustedDeliveries":0,"activeBans":2}`
		assert.JSONEq(t, want, string(encoded))
	})
}
