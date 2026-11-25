package maintenance

import (
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// RuntimeStatus describes the maintenance worker's in-process lifecycle.
type RuntimeStatus struct {
	// State is idle, processing, or stopped.
	State workerstate.State `json:"state" yaml:"state"`
	// StartedAt records when the worker goroutine was launched.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
}

// WorkerSnapshot reports worker lifecycle without querying SQLite.
func (r *Runner) WorkerSnapshot() RuntimeStatus {
	status := r.Snapshot()
	state := workerstate.StateIdle
	select {
	case <-r.done:
		state = workerstate.StateStopped
	default:
		if status.Prune.Running || status.Optimize.Running {
			state = workerstate.StateProcessing
		}
	}

	return RuntimeStatus{State: state, StartedAt: r.startedAt}
}
