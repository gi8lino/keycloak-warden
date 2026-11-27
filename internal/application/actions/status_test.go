package actions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// TestRunnerSnapshot covers action worker lifecycle reporting.
func TestRunnerSnapshot(t *testing.T) {
	t.Parallel()

	t.Run("reports idle worker", func(t *testing.T) {
		t.Parallel()

		started := time.Now().UTC()
		runner := &Runner{startedAt: started, done: make(chan struct{})}
		status := runner.Snapshot()

		assert.Equal(t, model.WorkerIdle, status.State)
		assert.Equal(t, started, status.StartedAt)
	})

	t.Run("reports a processing cycle", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.processing.Store(true)

		assert.Equal(t, model.WorkerProcessing, runner.Snapshot().State)
	})

	t.Run("reports stopped even after processing", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.processing.Store(true)
		close(runner.done)

		assert.Equal(t, model.WorkerStopped, runner.Snapshot().State)
	})
}
