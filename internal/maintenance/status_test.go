package maintenance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// TestSnapshotWorkerLifecycle verifies lifecycle and task state share one snapshot.
func TestSnapshotWorkerLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("reports idle with task schedules", func(t *testing.T) {
		t.Parallel()

		started := time.Now().UTC()
		runner := &Runner{
			startedAt: started,
			done:      make(chan struct{}),
			schedule: Schedule{
				PruneInterval:    time.Hour,
				OptimizeInterval: 24 * time.Hour,
			},
		}

		status := runner.Snapshot()

		assert.Equal(t, workerstate.StateIdle, status.State)
		assert.Equal(t, started, status.StartedAt)
		assert.Equal(t, "1h0m0s", status.PruneInterval)
		assert.Equal(t, "24h0m0s", status.OptimizeInterval)
		assert.False(t, status.Prune.Running)
	})

	t.Run("reports processing and current task state together", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.pruneStatus.Running = true

		status := runner.Snapshot()

		assert.Equal(t, workerstate.StateProcessing, status.State)
		assert.True(t, status.Prune.Running)
		assert.False(t, status.Optimize.Running)
	})

	t.Run("reports optimization as processing", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.optimizeStatus.Running = true

		status := runner.Snapshot()

		assert.Equal(t, workerstate.StateProcessing, status.State)
		assert.True(t, status.Optimize.Running)
	})

	t.Run("reports stopped after completion", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		close(runner.done)

		status := runner.Snapshot()

		assert.Equal(t, workerstate.StateStopped, status.State)
	})
}
