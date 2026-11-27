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

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// fakeQueue supplies an idle action worker and deterministic database statistics.
type fakeQueue struct {
	// stats is the persisted work summary.
	stats model.QueueStats
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

// Next returns no work for the running action worker.
func (fakeQueue) Next(context.Context, time.Time) (*actions.Job, error) { return nil, nil }

// Finish is unused because no provider jobs exist in the test.
func (fakeQueue) Finish(context.Context, actions.Job, error, int, time.Time, time.Duration) error {
	return nil
}

// fakeExpirer returns no ban expirations.
type fakeExpirer struct{}

// Expire leaves all persisted sources untouched.
func (fakeExpirer) Expire(context.Context, time.Time) ([]model.Decision, error) { return nil, nil }

// fakeMaintenanceStore accepts scheduled operations without accessing a database.
type fakeMaintenanceStore struct{}

// Prune acknowledges a scheduled observation cleanup.
func (fakeMaintenanceStore) Prune(context.Context, time.Time) error { return nil }

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
		actionsRunner := actions.Start(ctx, queue, fakeExpirer{}, nil, actions.DefaultRetryPolicy(), logger)
		defer func() { require.NoError(t, actionsRunner.Close()) }()
		maintenanceRunner := maintenance.Start(ctx, fakeMaintenanceStore{}, maintenance.Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: 24 * time.Hour,
		}, maintenance.MinObservationRetention, logger)
		defer maintenanceRunner.Close()

		service := NewWorkerService(actionsRunner, maintenanceRunner, queue)
		status, err := service.Snapshot(t.Context())

		require.NoError(t, err)
		assert.Contains(t, []model.WorkerState{model.WorkerIdle, model.WorkerProcessing}, status.Actions.State)
		assert.False(t, status.Actions.StartedAt.IsZero())
		assert.Equal(t, 2, status.Actions.PendingDeliveries)
		assert.Equal(t, 3, status.Actions.RetryingDeliveries)
		assert.Equal(t, 1, status.Actions.ExhaustedDeliveries)
		assert.Equal(t, 4, status.Actions.ActiveBans)
		require.NotNil(t, status.Actions.NextDeadline)
		assert.Equal(t, deadline, *status.Actions.NextDeadline)
		assert.Contains(t, []model.WorkerState{model.WorkerIdle, model.WorkerProcessing}, status.Maintenance.State)
		assert.False(t, status.Maintenance.StartedAt.IsZero())
		assert.Equal(t, "1h0m0s", status.Maintenance.PruneInterval)
	})

	t.Run("flattens embedded action fields in JSON", func(t *testing.T) {
		t.Parallel()

		startedAt := time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)
		lastAttemptAt := startedAt.Add(5 * time.Minute)
		nextDeadline := startedAt.Add(time.Hour)

		status := model.ActionWorker{
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
		actionsRunner := actions.Start(ctx, queue, fakeExpirer{}, nil, actions.DefaultRetryPolicy(), logger)
		defer func() { require.NoError(t, actionsRunner.Close()) }()
		maintenanceRunner := maintenance.Start(ctx, fakeMaintenanceStore{}, maintenance.Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: 24 * time.Hour,
		}, maintenance.MinObservationRetention, logger)
		defer maintenanceRunner.Close()

		status, err := NewWorkerService(actionsRunner, maintenanceRunner, queue).Snapshot(t.Context())

		require.ErrorContains(t, err, "storage error")
		assert.Equal(t, model.Workers{}, status)
	})
}
