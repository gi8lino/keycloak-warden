// Package workers exposes a read-only snapshot of Warden's two background workers.
package workers

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// Store supplies durable delivery counts and the next wake-up deadline.
type Store interface {
	// WorkerStats returns current-revision delivery counts and activity.
	WorkerStats(context.Context, time.Time) (actions.QueueStats, error)
	// NextDeadline returns the earliest due source expiry or delivery retry.
	NextDeadline(context.Context) (time.Time, error)
}

// Actions is the action worker's runtime state and durable queue summary.
type Actions struct {
	// State is idle, processing, or stopped.
	State workerstate.State `json:"state" yaml:"state"`
	// StartedAt is the start of the current worker process.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
	// PendingDeliveries counts current pending destination revisions.
	PendingDeliveries int `json:"pendingDeliveries" yaml:"pendingDeliveries"`
	// RetryingDeliveries counts current retrying destination revisions.
	RetryingDeliveries int `json:"retryingDeliveries" yaml:"retryingDeliveries"`
	// ExhaustedDeliveries counts current exhausted destination revisions.
	ExhaustedDeliveries int `json:"exhaustedDeliveries" yaml:"exhaustedDeliveries"`
	// ActiveBans counts addresses with at least one unexpired ban source.
	ActiveBans int `json:"activeBans" yaml:"activeBans"`
	// NextDeadline is the earliest pending delivery or source expiry.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
	// LastAttemptAt is the latest completed delivery attempt, including previous runs.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
}

// Maintenance is the maintenance worker's runtime state and task history.
type Maintenance struct {
	// State is idle, processing, or stopped.
	State workerstate.State `json:"state" yaml:"state"`
	// StartedAt is the start of the current maintenance process.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
	// Prune is the last observation cleanup attempt.
	Prune maintenance.TaskStatus `json:"prune" yaml:"prune"`
	// Optimize is the last SQLite optimization attempt.
	Optimize maintenance.TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval is the configured cleanup cadence.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval is the configured optimization cadence.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
}

// Status is the combined observable worker state for administrators.
type Status struct {
	// Actions handles expiry, ban deliveries, and retries.
	Actions Actions `json:"actions" yaml:"actions"`
	// Maintenance handles periodic observation cleanup and SQLite optimization.
	Maintenance Maintenance `json:"maintenance" yaml:"maintenance"`
}

// Service collects status from the existing runners and SQLite; it starts no workers.
type Service struct {
	// actions is the action worker lifecycle owner.
	actions *actions.Runner
	// maintenance is the maintenance worker lifecycle owner.
	maintenance *maintenance.Runner
	// store is the persistent work queue.
	store Store
}

// NewService composes the two runners with their existing durable queue.
func NewService(actionRunner *actions.Runner, maintenanceRunner *maintenance.Runner, store Store) *Service {
	return &Service{actions: actionRunner, maintenance: maintenanceRunner, store: store}
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

	action := s.actions.Snapshot()
	maintenanceWorker := s.maintenance.WorkerSnapshot()
	maintenanceStatus := s.maintenance.Snapshot()

	result := Status{
		Actions: Actions{
			State:               action.State,
			StartedAt:           action.StartedAt,
			PendingDeliveries:   stats.PendingDeliveries,
			RetryingDeliveries:  stats.RetryingDeliveries,
			ExhaustedDeliveries: stats.ExhaustedDeliveries,
			ActiveBans:          stats.ActiveBans,
			LastAttemptAt:       stats.LastAttemptAt,
		},
		Maintenance: Maintenance{
			State:            maintenanceWorker.State,
			StartedAt:        maintenanceWorker.StartedAt,
			Prune:            maintenanceStatus.Prune,
			Optimize:         maintenanceStatus.Optimize,
			PruneInterval:    maintenanceStatus.PruneInterval,
			OptimizeInterval: maintenanceStatus.OptimizeInterval,
		},
	}
	if !deadline.IsZero() {
		utc := deadline.UTC()
		result.Actions.NextDeadline = &utc
	}
	return result, nil
}
