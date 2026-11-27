package sqlite

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// queueIncident records an occurrence and returns its initial delivery job.
func queueIncident(t *testing.T, store *Store, now time.Time) notifications.Job {
	t.Helper()

	ctx := t.Context()
	require.NoError(t, store.BindNotificationIdentities(ctx, map[string]string{"audit": "receiver"}))
	rule := ipRule(t, "audit", 1, 0)
	rule.Actions.Notify = []string{"audit"}
	service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{})
	require.NoError(t, err)
	_, err = service.Process(ctx, namedLogin(t, "one", "hq", "user", "203.0.113.1", now), func() time.Time { return now })
	require.NoError(t, err)
	job, err := store.NextNotification(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	return *job
}

func TestNotificationHistory(t *testing.T) {
	t.Parallel()

	t.Run("records attempts and retry history with a fresh budget", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		job := queueIncident(t, store, now)
		failure := errors.New("receiver unavailable")
		require.NoError(t, store.FinishNotification(ctx, job, notifications.Complete(job, failure, 1, now, time.Second)))
		stats, err := store.NotificationStats(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, stats.ExhaustedDeliveries)
		require.NotNil(t, stats.LastAttemptAt)
		assert.Equal(t, now, *stats.LastAttemptAt)

		view := overview.NewNotificationService(store)
		page, err := view.Deliveries(ctx, 0)
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		assert.Equal(t, model.DeliveryExhausted, page.Items[0].Status)
		assert.Equal(t, "receiver unavailable", page.Items[0].LastError)
		retry := notifications.NewRetryService(store, map[string]notifications.Target{"audit": {Identity: "receiver"}})
		require.NoError(t, retry.Retry(ctx, job.ID, "operator", now.Add(time.Second)))
		require.ErrorIs(t, retry.Retry(ctx, job.ID, "operator", now.Add(time.Second)), notifications.ErrRetryConflict)
		stats, err = store.NotificationStats(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, stats.PendingDeliveries)
		assert.Zero(t, stats.ExhaustedDeliveries)
		require.NotNil(t, stats.NextDeadline)
		assert.Equal(t, now.Add(time.Second), *stats.NextDeadline)

		next, err := store.NextNotification(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, next)
		assert.Equal(t, 1, next.Attempts)
		assert.Equal(t, 1, next.RetryBaseline)
		require.NoError(t, store.FinishNotification(ctx, *next, notifications.Complete(*next, nil, 1, now.Add(time.Second), time.Second)))
		attempts, err := view.Attempts(ctx, job.ID, 0)
		require.NoError(t, err)
		require.Len(t, attempts.Items, 2)
		assert.Equal(t, 2, attempts.Items[0].Number)
		assert.Empty(t, attempts.Items[0].Error)
		assert.Equal(t, 1, attempts.Items[1].Number)
		assert.Equal(t, failure.Error(), attempts.Items[1].Error)
		var actor string
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT actor FROM notification_retries WHERE delivery_id = ?", job.ID).Scan(&actor))
		assert.Equal(t, "operator", actor)
	})

	t.Run("rejects a retry to a reassigned destination", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		job := queueIncident(t, store, now)
		require.NoError(t, store.FinishNotification(ctx, job, notifications.Complete(job, errors.New("failed"), 1, now, time.Second)))
		require.NoError(t, store.BindNotificationIdentities(ctx, map[string]string{"audit": "different receiver"}))
		service := notifications.NewRetryService(store, map[string]notifications.Target{"audit": {Identity: "different receiver"}})
		require.ErrorIs(t, service.Retry(ctx, job.ID, "operator", now), notifications.ErrRetryConflict)
		pending, err := store.NextNotification(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, pending)
	})

	t.Run("prunes completed jobs and their attempt history together", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		job := queueIncident(t, store, now)
		require.NoError(t, store.FinishNotification(ctx, job, notifications.Complete(job, nil, 1, now, time.Second)))
		require.NoError(t, store.Prune(ctx, now, now))
		items, err := store.ListNotifications(ctx, 0, 20)
		require.NoError(t, err)
		assert.Empty(t, items)
		attempts, err := store.ListNotificationAttempts(ctx, job.ID, 0, 20)
		require.NoError(t, err)
		assert.Empty(t, attempts)
	})
}
