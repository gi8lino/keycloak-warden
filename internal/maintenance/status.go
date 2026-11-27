package maintenance

import (
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// RuntimeStatus describes the maintenance worker's in-process lifecycle.
type RuntimeStatus struct {
	// State is idle, processing, or stopped.
	State model.WorkerState `json:"state" yaml:"state"`
	// StartedAt records when the worker goroutine was launched.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
}

// WorkerSnapshot reports worker lifecycle without querying SQLite.
func (r *Runner) WorkerSnapshot() RuntimeStatus {
	status := r.Snapshot()
	state := model.WorkerIdle
	select {
	case <-r.done:
		state = model.WorkerStopped
	default:
		if status.Prune.Running || status.Optimize.Running {
			state = model.WorkerProcessing
		}
	}

	return RuntimeStatus{
		State:     state,
		StartedAt: r.startedAt,
	}
}
