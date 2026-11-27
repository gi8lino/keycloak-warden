package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWorkersJSON(t *testing.T) {
	t.Parallel()

	t.Run("decodes existing flat worker responses", func(t *testing.T) {
		t.Parallel()

		var workers Workers
		data := []byte(`{"actions":{"state":"idle","startedAt":"2026-11-25T08:00:00Z","pendingDeliveries":3,"activeBans":2},"maintenance":{"state":"processing","startedAt":"2026-11-25T08:00:00Z","prune":{"running":true},"pruneInterval":"1h0m0s"}}`)
		if err := json.Unmarshal(data, &workers); err != nil {
			t.Fatal(err)
		}
		if workers.Actions.State != WorkerIdle || workers.Actions.PendingDeliveries != 3 || workers.Actions.ActiveBans != 2 {
			t.Fatalf("unexpected action worker: %+v", workers.Actions)
		}
		if workers.Maintenance.State != WorkerProcessing || !workers.Maintenance.Prune.Running || workers.Maintenance.PruneInterval != "1h0m0s" {
			t.Fatalf("unexpected maintenance worker: %+v", workers.Maintenance)
		}
	})

	t.Run("encodes embedded action fields at the top level", func(t *testing.T) {
		t.Parallel()

		worker := ActionWorker{
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
		if err != nil {
			t.Fatal(err)
		}

		const want = `{"state":"idle","startedAt":"2026-11-25T08:00:00Z","pendingDeliveries":3,"retryingDeliveries":0,"exhaustedDeliveries":0,"activeBans":2}`
		if string(encoded) != want {
			t.Fatalf("got %s, want %s", encoded, want)
		}
	})
}
