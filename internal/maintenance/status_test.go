package maintenance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// TestWorkerSnapshot covers maintenance lifecycle and ongoing operation status.
func TestWorkerSnapshot(t *testing.T) {
	t.Parallel()

	t.Run("reports idle", func(t *testing.T) {
		t.Parallel()

		started := time.Now().UTC()
		runner := &Runner{done: make(chan struct{}), startedAt: started}

		assert.Equal(t, RuntimeStatus{State: workerstate.StateIdle, StartedAt: started}, runner.WorkerSnapshot())
	})

	t.Run("reports processing", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.pruneStatus.Running = true

		assert.Equal(t, workerstate.StateProcessing, runner.WorkerSnapshot().State)
	})

	t.Run("reports stopped", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		close(runner.done)

		assert.Equal(t, workerstate.StateStopped, runner.WorkerSnapshot().State)
	})
}
