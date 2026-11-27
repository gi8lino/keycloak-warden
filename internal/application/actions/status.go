package actions

import "github.com/gi8lino/keycloak-warden/pkg/model"

// Snapshot returns a concurrency-safe view without inspecting the delivery queue.
func (r *Runner) Snapshot() model.RuntimeStatus {
	state := model.WorkerIdle
	select {
	case <-r.done:
		state = model.WorkerStopped
	default:
		if r.processing.Load() {
			state = model.WorkerProcessing
		}
	}

	return model.RuntimeStatus{
		State:     state,
		StartedAt: r.startedAt,
	}
}
