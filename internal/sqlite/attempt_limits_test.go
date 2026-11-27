package sqlite_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestReconcileAttemptLimit(t *testing.T) {
	t.Parallel()

	t.Run("decreasing limit exhausts previously retryable work", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := bans.ApplyManualBan(ctx, store, "192.0.2.10", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), 3, now, actions.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, model.DeliveryRetrying, view.DeliveryHistory[0].Status)

		err = store.ReconcileAttemptLimit(ctx, "webhook.receiver", 1)
		require.NoError(t, err)

		view, err = store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, model.DeliveryExhausted, view.DeliveryHistory[0].Status)
		assert.Len(t, view.DeliveryHistory[0].Attempts, 1)
		assert.Nil(t, view.DeliveryHistory[0].NextAttemptAt)
	})

	t.Run("increasing limit restores only current exhausted work", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := bans.ApplyManualBan(ctx, store, "192.0.2.11", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), 1, now, actions.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, model.DeliveryExhausted, view.DeliveryHistory[0].Status)

		require.NoError(t, store.ReconcileAttemptLimit(ctx, "webhook.receiver", 2))

		view, err = store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, model.DeliveryRetrying, view.DeliveryHistory[0].Status)
		assert.Len(t, view.DeliveryHistory[0].Attempts, 1)
		assert.NotNil(t, view.DeliveryHistory[0].NextAttemptAt)
	})

	t.Run("does not reactivate superseded revisions", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := bans.ApplyManualBan(ctx, store, "192.0.2.12", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), 3, now, actions.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
		_, err = bans.ApplyManualBan(ctx, store, "192.0.2.12", now.Add(2*time.Hour), "extended", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		require.NoError(t, store.ReconcileAttemptLimit(ctx, "webhook.receiver", 5))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 2)
		assert.Equal(t, model.DeliveryPending, view.DeliveryHistory[0].Status)
		assert.Equal(t, model.DeliverySuperseded, view.DeliveryHistory[1].Status)
	})

	t.Run("reconciles only the named destination", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver", "webhook.teams")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := bans.ApplyManualBan(ctx, store, "192.0.2.14", now.Add(time.Hour), "test", now, []string{"webhook.receiver", "webhook.teams"})
		require.NoError(t, err)

		receiverJob, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, receiverJob)
		assert.Equal(t, "webhook.receiver", receiverJob.Destination)
		require.NoError(t, store.Finish(ctx, *receiverJob, errors.New("unavailable"), 1, now, actions.DefaultRetryPolicy().NextDelay(receiverJob.PreviousDelay)))

		teamsJob, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, teamsJob)
		assert.Equal(t, "webhook.teams", teamsJob.Destination)
		require.NoError(t, store.Finish(ctx, *teamsJob, errors.New("unavailable"), 1, now, actions.DefaultRetryPolicy().NextDelay(teamsJob.PreviousDelay)))

		require.NoError(t, store.ReconcileAttemptLimit(ctx, "webhook.receiver", 2))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 2)
		assert.Equal(t, "webhook.receiver", view.DeliveryHistory[0].Destination)
		assert.Equal(t, model.DeliveryRetrying, view.DeliveryHistory[0].Status)
		assert.Equal(t, "webhook.teams", view.DeliveryHistory[1].Destination)
		assert.Equal(t, model.DeliveryExhausted, view.DeliveryHistory[1].Status)
	})

	t.Run("rejects invalid limit without changing the database", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := bans.ApplyManualBan(ctx, store, "192.0.2.13", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.ErrorContains(t, store.Finish(ctx, *job, errors.New("unavailable"), 0, now, actions.DefaultRetryPolicy().NextDelay(job.PreviousDelay)), "max-attempts")

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Empty(t, view.DeliveryHistory[0].Attempts)

		err = store.ReconcileAttemptLimit(ctx, "webhook.receiver", 0)
		require.ErrorContains(t, err, "max-attempts")
	})

	t.Run("accepts a destination with no delivery history", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })

		// SQLite knows delivery history, not which targets are configured.
		err := store.ReconcileAttemptLimit(t.Context(), "webhook.new", 2)

		require.NoError(t, err)
	})
}

// TestDeliveryStatusConstraint ensures the database never persists an unknown
// delivery status, independently of the Go enum's validity method.
func TestDeliveryStatusConstraint(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.db")
	store, _ := openStore(t, path, "edge")
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)
	created, err := bans.ApplyManualBan(t.Context(), store, "203.0.113.88", now.Add(time.Hour), "incident", now, []string{"edge"})
	require.NoError(t, err)

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err = db.ExecContext(t.Context(), "UPDATE delivery_history SET status = ? WHERE ip = ?", "unknown", created.Decision.IP)
	require.Error(t, err)

	record, err := store.GetDecision(t.Context(), created.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, record.DeliveryHistory, 1)
	assert.Equal(t, model.DeliveryPending, record.DeliveryHistory[0].Status)
}
