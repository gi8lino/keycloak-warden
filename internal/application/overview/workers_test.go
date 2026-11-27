package overview

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// fakeQueue supplies an idle enforcement worker and deterministic database statistics.
type fakeQueue struct {
	// stats is the persisted work summary.
	stats model.QueueStats
	// notificationStats holds persisted incident delivery counts.
	notificationStats model.NotificationWorker
	// deadline is the earliest scheduled queue deadline.
	deadline time.Time
	// err makes the read-only query fail.
	err error
}

// Changes is nil because the test worker wakes only for shutdown.
func (fakeQueue) Changes() <-chan struct{} { return nil }

// NextDeadline returns the persisted next deadline.
func (q fakeQueue) NextDeadline(context.Context) (time.Time, error) { return q.deadline, q.err }

// WorkerStats returns the fake current-revision delivery counts.
func (q fakeQueue) WorkerStats(context.Context, time.Time) (model.QueueStats, error) {
	return q.stats, q.err
}

// NotificationStats returns the independent notification queue summary.
func (q fakeQueue) NotificationStats(context.Context) (model.NotificationWorker, error) {
	return q.notificationStats, q.err
}

// Next returns no work for the running enforcement worker.
func (fakeQueue) Next(context.Context, time.Time) (*enforcement.Job, error) { return nil, nil }

// Finish is unused because no provider jobs exist in the test.
func (fakeQueue) Finish(context.Context, enforcement.Job, error, enforcement.AttemptLimit, time.Time, time.Duration) error {
	return nil
}

// fakeExpirer returns no ban expirations.
type fakeExpirer struct{}

// Expire leaves all persisted sources untouched.
func (fakeExpirer) Expire(context.Context, time.Time) ([]model.Decision, error) { return nil, nil }

// fakeMaintenanceStore accepts scheduled operations without accessing a database.
type fakeMaintenanceStore struct{}

// Prune acknowledges a scheduled observation cleanup.
func (fakeMaintenanceStore) Prune(context.Context, time.Time, time.Time) error { return nil }

// Optimize acknowledges a planned SQLite optimize operation.
func (fakeMaintenanceStore) Optimize(context.Context) error { return nil }

func TestWorkerSnapshot(t *testing.T) {
	t.Parallel()

	t.Run("aggregates runner states and persistent queue counts", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		deadline := time.Now().Add(time.Hour).UTC()
		queue := fakeQueue{
			stats: model.QueueStats{
				PendingDeliveries:   2,
				RetryingDeliveries:  3,
				ExhaustedDeliveries: 1,
				ActiveBans:          4,
			},
			deadline: deadline,
		}
		enforcementRunner := enforcement.Start(ctx, queue, fakeExpirer{}, nil, retry.DefaultRetryPolicy(), logger)
		defer func() { require.NoError(t, enforcementRunner.Close()) }()
		maintenanceRunner := maintenance.Start(ctx, fakeMaintenanceStore{}, maintenance.Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: 24 * time.Hour,
		}, maintenance.Retention{Observations: maintenance.MinObservationRetention, Incidents: 30 * 24 * time.Hour}, logger)
		defer maintenanceRunner.Close()

		service := NewWorkerService(enforcementRunner, nil, maintenanceRunner, queue)
		status, err := service.Snapshot(t.Context())

		require.NoError(t, err)
		assert.Contains(t, []model.WorkerState{model.WorkerIdle, model.WorkerProcessing}, status.Enforcement.State)
		assert.False(t, status.Enforcement.StartedAt.IsZero())
		assert.Equal(t, 2, status.Enforcement.PendingDeliveries)
		assert.Equal(t, 3, status.Enforcement.RetryingDeliveries)
		assert.Equal(t, 1, status.Enforcement.ExhaustedDeliveries)
		assert.Equal(t, 4, status.Enforcement.ActiveBans)
		require.NotNil(t, status.Enforcement.NextDeadline)
		assert.Equal(t, deadline, *status.Enforcement.NextDeadline)
		assert.Contains(t, []model.WorkerState{model.WorkerIdle, model.WorkerProcessing}, status.Maintenance.State)
		assert.False(t, status.Maintenance.StartedAt.IsZero())
		assert.Equal(t, "1h0m0s", status.Maintenance.PruneInterval)
	})

	t.Run("flattens embedded enforcement fields in JSON", func(t *testing.T) {
		t.Parallel()

		startedAt := time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)
		lastAttemptAt := startedAt.Add(5 * time.Minute)
		nextDeadline := startedAt.Add(time.Hour)

		status := model.EnforcementWorker{
			RuntimeStatus: model.RuntimeStatus{
				State:     model.WorkerIdle,
				StartedAt: startedAt,
			},
			QueueStats: model.QueueStats{
				PendingDeliveries:   2,
				RetryingDeliveries:  3,
				ExhaustedDeliveries: 1,
				ActiveBans:          4,
				LastAttemptAt:       &lastAttemptAt,
			},
			NextDeadline: &nextDeadline,
		}

		encoded, err := json.Marshal(status)

		require.NoError(t, err)
		assert.JSONEq(t, `{
			"state": "idle",
			"startedAt": "2026-11-25T08:00:00Z",
			"pendingDeliveries": 2,
			"retryingDeliveries": 3,
			"exhaustedDeliveries": 1,
			"activeBans": 4,
			"lastAttemptAt": "2026-11-25T08:05:00Z",
			"nextDeadline": "2026-11-25T09:00:00Z"
		}`, string(encoded))
	})

	t.Run("fails without inventing a partial worker snapshot", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		queue := fakeQueue{err: errors.New("storage error")}
		enforcementRunner := enforcement.Start(ctx, queue, fakeExpirer{}, nil, retry.DefaultRetryPolicy(), logger)
		defer func() { require.NoError(t, enforcementRunner.Close()) }()
		maintenanceRunner := maintenance.Start(ctx, fakeMaintenanceStore{}, maintenance.Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: 24 * time.Hour,
		}, maintenance.Retention{Observations: maintenance.MinObservationRetention, Incidents: 30 * 24 * time.Hour}, logger)
		defer maintenanceRunner.Close()

		status, err := NewWorkerService(enforcementRunner, nil, maintenanceRunner, queue).Snapshot(t.Context())

		require.ErrorContains(t, err, "storage error")
		assert.Equal(t, model.Workers{}, status)
	})
}

// runtimeSnapshotStub supplies lifecycle state without starting an enforcement worker.
type runtimeSnapshotStub struct {
	// status is the observable lifecycle snapshot.
	status model.RuntimeStatus
}

// Snapshot returns the configured lifecycle state.
func (s runtimeSnapshotStub) Snapshot() model.RuntimeStatus { return s.status }

// maintenanceSnapshotStub supplies scheduler state without owning a scheduler.
type maintenanceSnapshotStub struct {
	// status is the observable maintenance snapshot.
	status model.Maintenance
}

// Snapshot returns the configured scheduler state.
func (s maintenanceSnapshotStub) Snapshot() model.Maintenance { return s.status }

func TestWorkerSnapshotInterfaces(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	enforcement := model.RuntimeStatus{
		State:     model.WorkerIdle,
		StartedAt: started,
	}
	notification := model.RuntimeStatus{
		State:     model.WorkerProcessing,
		StartedAt: started,
	}
	maintenance := model.Maintenance{State: model.WorkerProcessing, StartedAt: started}
	service := NewWorkerService(runtimeSnapshotStub{status: enforcement}, runtimeSnapshotStub{status: notification}, maintenanceSnapshotStub{status: maintenance}, fakeQueue{notificationStats: model.NotificationWorker{PendingDeliveries: 3}})
	result, err := service.Snapshot(t.Context())
	require.NoError(t, err)
	assert.Equal(t, enforcement, result.Enforcement.RuntimeStatus)
	require.NotNil(t, result.Notifications.Runtime)
	assert.Equal(t, notification, *result.Notifications.Runtime)
	assert.Equal(t, 3, result.Notifications.PendingDeliveries)
	assert.Equal(t, maintenance, result.Maintenance)
}
