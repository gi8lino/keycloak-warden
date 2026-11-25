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

// QueueStats describes durable outstanding work and the most recent completed attempt.
type QueueStats struct {
	// PendingDeliveries counts current revisions not yet attempted.
	PendingDeliveries int `json:"pendingDeliveries" yaml:"pendingDeliveries"`
	// RetryingDeliveries counts current revisions waiting for another attempt.
	RetryingDeliveries int `json:"retryingDeliveries" yaml:"retryingDeliveries"`
	// ExhaustedDeliveries counts current revisions whose attempt budgets were consumed.
	ExhaustedDeliveries int `json:"exhaustedDeliveries" yaml:"exhaustedDeliveries"`
	// ActiveBans counts addresses with at least one unexpired ban source.
	ActiveBans int `json:"activeBans" yaml:"activeBans"`
	// LastAttemptAt is the latest completed attempt across all revisions and runs.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
}
