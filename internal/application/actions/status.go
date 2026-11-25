package actions

import (
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// RuntimeStatus describes the action worker's in-process lifecycle.
type RuntimeStatus struct {
	// State is idle, processing, or stopped.
	State workerstate.State `json:"state" yaml:"state"`
	// StartedAt records when the worker goroutine was launched.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
}

// Snapshot returns a concurrency-safe view without inspecting the delivery queue.
func (r *Runner) Snapshot() RuntimeStatus {
	state := workerstate.StateIdle
	select {
	case <-r.done:
		state = workerstate.StateStopped
	default:
		if r.processing.Load() {
			state = workerstate.StateProcessing
		}
	}

	return RuntimeStatus{State: state, StartedAt: r.startedAt}
}
