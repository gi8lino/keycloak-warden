// Package workers exposes a read-only snapshot of Warden's two background workers.
package workers

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// Store supplies durable delivery counts and the next wake-up deadline.
type Store interface {
	// WorkerStats returns current-revision delivery counts and activity.
	WorkerStats(context.Context, time.Time) (QueueStats, error)
	// NextDeadline returns the earliest due source expiry or delivery retry.
	NextDeadline(context.Context) (time.Time, error)
}

// Actions is the action worker's runtime state and durable queue summary.
type Actions struct {
	// RuntimeStatus supplies the in-process lifecycle state.
	actions.RuntimeStatus `yaml:",inline"`
	// QueueStats supplies the persisted delivery and ban statistics.
	QueueStats `yaml:",inline"`
	// NextDeadline is the earliest pending delivery or source expiry.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
}

// Status is the combined observable worker state for administrators.
type Status struct {
	// Actions handles expiry, ban deliveries, and retries.
	Actions Actions `json:"actions" yaml:"actions"`
	// Maintenance handles periodic observation cleanup and SQLite optimization.
	Maintenance maintenance.Status `json:"maintenance" yaml:"maintenance"`
}

// Service collects worker lifecycle and queue statistics.
type Service struct {
	// actions is the action worker lifecycle owner.
	actions *actions.Runner
	// maintenance is the maintenance worker lifecycle owner.
	maintenance *maintenance.Runner
	// store is the persistent work queue.
	store Store
}

// NewService creates a worker status service.
func NewService(
	actionRunner *actions.Runner,
	maintenanceRunner *maintenance.Runner,
	store Store,
) *Service {
	return &Service{
		actions:     actionRunner,
		maintenance: maintenanceRunner,
		store:       store,
	}
}

// Snapshot returns a point-in-time view; queue counts can change between queries.
func (s *Service) Snapshot(ctx context.Context) (Status, error) {
	stats, err := s.store.WorkerStats(ctx, time.Now())
	if err != nil {
		return Status{}, err
	}

	deadline, err := s.store.NextDeadline(ctx)
	if err != nil {
		return Status{}, err
	}

	result := Status{
		Actions: Actions{
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
