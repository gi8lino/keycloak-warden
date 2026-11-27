package overview

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// WorkerStore supplies durable delivery counts and the next wake-up deadline.
type WorkerStore interface {
	// WorkerStats returns current-revision delivery counts and activity.
	WorkerStats(context.Context, time.Time) (QueueStats, error)
	// NextDeadline returns the earliest due source expiry or delivery retry.
	NextDeadline(context.Context) (time.Time, error)
}

// ActionWorkerStatus is the action worker's runtime state and durable queue summary.
type ActionWorkerStatus struct {
	// RuntimeStatus supplies the in-process lifecycle state.
	actions.RuntimeStatus `yaml:",inline"`
	// QueueStats supplies the persisted delivery and ban statistics.
	QueueStats `yaml:",inline"`
	// NextDeadline is the earliest pending delivery or source expiry.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
}

// WorkerStatus is the combined observable worker state for administrators.
type WorkerStatus struct {
	// Actions handles expiry, ban deliveries, and retries.
	Actions ActionWorkerStatus `json:"actions" yaml:"actions"`
	// Maintenance handles periodic observation cleanup and SQLite optimization.
	Maintenance maintenance.Status `json:"maintenance" yaml:"maintenance"`
}

// WorkerService collects worker lifecycle and queue statistics.
type WorkerService struct {
	// actions is the action worker lifecycle owner.
	actions *actions.Runner
	// maintenance is the maintenance worker lifecycle owner.
	maintenance *maintenance.Runner
	// store is the persistent work queue.
	store WorkerStore
}

// NewWorkerService creates a worker status service.
func NewWorkerService(
	actionRunner *actions.Runner,
	maintenanceRunner *maintenance.Runner,
	store WorkerStore,
) *WorkerService {
	return &WorkerService{
		actions:     actionRunner,
		maintenance: maintenanceRunner,
		store:       store,
	}
}

// Snapshot returns a point-in-time view; queue counts can change between queries.
func (s *WorkerService) Snapshot(ctx context.Context) (WorkerStatus, error) {
	stats, err := s.store.WorkerStats(ctx, time.Now())
	if err != nil {
		return WorkerStatus{}, err
	}

	deadline, err := s.store.NextDeadline(ctx)
	if err != nil {
		return WorkerStatus{}, err
	}

	result := WorkerStatus{
		Actions: ActionWorkerStatus{
			RuntimeStatus: s.actions.Snapshot(),
			QueueStats:    stats,
		},
		Maintenance: s.maintenance.Snapshot(),
	}

	if !deadline.IsZero() {
		result.Actions.NextDeadline = new(deadline.UTC())
	}

	return result, nil
}
