package overview

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// WorkerStore supplies durable delivery counts and the next wake-up deadline.
type WorkerStore interface {
	// WorkerStats returns current-revision delivery counts and activity.
	WorkerStats(context.Context, time.Time) (model.QueueStats, error)
	// NextDeadline returns the earliest due source expiry or delivery retry.
	NextDeadline(context.Context) (time.Time, error)
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
