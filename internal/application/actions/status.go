package actions

import (
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// RuntimeStatus describes the action worker's in-process lifecycle.
type RuntimeStatus struct {
	// State is idle, processing, or stopped.
	State model.WorkerState `json:"state" yaml:"state"`
	// StartedAt records when the worker goroutine was launched.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
}

// Snapshot returns a concurrency-safe view without inspecting the delivery queue.
func (r *Runner) Snapshot() RuntimeStatus {
	state := model.WorkerIdle
	select {
	case <-r.done:
		state = model.WorkerStopped
	default:
		if r.processing.Load() {
			state = model.WorkerProcessing
		}
	}

	return RuntimeStatus{
		State:     state,
		StartedAt: r.startedAt,
	}
}
