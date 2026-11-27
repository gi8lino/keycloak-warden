package overview

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// WorkerStore supplies durable delivery counts and the next wake-up deadline.
type WorkerStore interface {
	// WorkerStats returns current-revision delivery counts and activity.
	WorkerStats(context.Context, time.Time) (model.QueueStats, error)
	// NextDeadline returns the earliest due source expiry or delivery retry.
	NextDeadline(context.Context) (time.Time, error)
}

// ActionSnapshot supplies read-only action worker lifecycle information.
type ActionSnapshot interface {
	// Snapshot returns the current action worker state.
	Snapshot() model.RuntimeStatus
}

// MaintenanceSnapshot supplies read-only maintenance worker information.
type MaintenanceSnapshot interface {
	// Snapshot returns the current maintenance scheduler state.
	Snapshot() model.Maintenance
}

// WorkerService collects worker lifecycle and queue statistics.
type WorkerService struct {
	// actions observes the action worker lifecycle.
	actions ActionSnapshot
	// maintenance observes the maintenance scheduler.
	maintenance MaintenanceSnapshot
	// store is the persistent work queue.
	store WorkerStore
}

// NewWorkerService creates a worker status service.
func NewWorkerService(
	actionRunner ActionSnapshot,
	maintenanceRunner MaintenanceSnapshot,
	store WorkerStore,
) *WorkerService {
	return &WorkerService{
		actions:     actionRunner,
		maintenance: maintenanceRunner,
		store:       store,
	}
}

// Snapshot returns a point-in-time view; queue counts can change between queries.
func (s *WorkerService) Snapshot(ctx context.Context) (model.Workers, error) {
	stats, err := s.store.WorkerStats(ctx, time.Now())
	if err != nil {
		return model.Workers{}, err
	}

	deadline, err := s.store.NextDeadline(ctx)
	if err != nil {
		return model.Workers{}, err
	}

	result := model.Workers{
		Actions: model.ActionWorker{
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
