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
	// NotificationStats returns incident delivery counts and deadlines.
	NotificationStats(context.Context) (model.NotificationWorker, error)
}

// RuntimeSnapshot supplies read-only delivery worker lifecycle information.
type RuntimeSnapshot interface {
	// Snapshot returns the current delivery worker state.
	Snapshot() model.RuntimeStatus
}

// MaintenanceSnapshot supplies read-only maintenance worker information.
type MaintenanceSnapshot interface {
	// Snapshot returns the current maintenance scheduler state.
	Snapshot() model.Maintenance
}

// WorkerService collects worker lifecycle and queue statistics.
type WorkerService struct {
	// enforcement observes the enforcement worker lifecycle.
	enforcement RuntimeSnapshot
	// notifications observes the optional notification worker.
	notifications RuntimeSnapshot
	// maintenance observes the maintenance scheduler.
	maintenance MaintenanceSnapshot
	// store is the persistent work queue.
	store WorkerStore
}

// NewWorkerService creates a worker status service.
func NewWorkerService(
	enforcementRunner RuntimeSnapshot,
	notificationRunner RuntimeSnapshot,
	maintenanceRunner MaintenanceSnapshot,
	store WorkerStore,
) *WorkerService {
	return &WorkerService{
		enforcement:   enforcementRunner,
		notifications: notificationRunner,
		maintenance:   maintenanceRunner,
		store:         store,
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

	notificationStats, err := s.store.NotificationStats(ctx)
	if err != nil {
		return model.Workers{}, err
	}
	if s.notifications != nil {
		status := s.notifications.Snapshot()
		notificationStats.Runtime = &status
	}

	result := model.Workers{
		Notifications: notificationStats,
		Enforcement: model.EnforcementWorker{
			RuntimeStatus: s.enforcement.Snapshot(),
			QueueStats:    stats,
		},
		Maintenance: s.maintenance.Snapshot(),
	}

	if !deadline.IsZero() {
		result.Enforcement.NextDeadline = new(deadline.UTC())
	}

	return result, nil
}
