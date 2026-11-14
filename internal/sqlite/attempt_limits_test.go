package sqlite_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconcileAttemptLimit(t *testing.T) {
	t.Parallel()

	t.Run("decreasing limit exhausts previously retryable work", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := store.ApplyManualBan(ctx, "192.0.2.10", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), 3, now))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, "retrying", view.DeliveryHistory[0].Status)

		err = store.ReconcileAttemptLimit(ctx, "webhook.receiver", 1)
		require.NoError(t, err)

		view, err = store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, "exhausted", view.DeliveryHistory[0].Status)
		assert.Len(t, view.DeliveryHistory[0].Attempts, 1)
		assert.Nil(t, view.DeliveryHistory[0].NextAttemptAt)
	})

	t.Run("increasing limit restores only current exhausted work", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := store.ApplyManualBan(ctx, "192.0.2.11", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), 1, now))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, "exhausted", view.DeliveryHistory[0].Status)

		require.NoError(t, store.ReconcileAttemptLimit(ctx, "webhook.receiver", 2))

		view, err = store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Equal(t, "retrying", view.DeliveryHistory[0].Status)
		assert.Len(t, view.DeliveryHistory[0].Attempts, 1)
		assert.NotNil(t, view.DeliveryHistory[0].NextAttemptAt)
	})

	t.Run("does not reactivate superseded revisions", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := store.ApplyManualBan(ctx, "192.0.2.12", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), 3, now))
		_, err = store.ApplyManualBan(ctx, "192.0.2.12", now.Add(2*time.Hour), "extended", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		require.NoError(t, store.ReconcileAttemptLimit(ctx, "webhook.receiver", 5))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 2)
		assert.Equal(t, "pending", view.DeliveryHistory[0].Status)
		assert.Equal(t, "superseded", view.DeliveryHistory[1].Status)
	})

	t.Run("reconciles only the named destination", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver", "webhook.teams")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := store.ApplyManualBan(ctx, "192.0.2.14", now.Add(time.Hour), "test", now, []string{"webhook.receiver", "webhook.teams"})
		require.NoError(t, err)

		receiverJob, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, receiverJob)
		assert.Equal(t, "webhook.receiver", receiverJob.Destination)
		require.NoError(t, store.Finish(ctx, *receiverJob, errors.New("unavailable"), 1, now))

		teamsJob, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, teamsJob)
		assert.Equal(t, "webhook.teams", teamsJob.Destination)
		require.NoError(t, store.Finish(ctx, *teamsJob, errors.New("unavailable"), 1, now))

		require.NoError(t, store.ReconcileAttemptLimit(ctx, "webhook.receiver", 2))

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 2)
		assert.Equal(t, "webhook.receiver", view.DeliveryHistory[0].Destination)
		assert.Equal(t, "retrying", view.DeliveryHistory[0].Status)
		assert.Equal(t, "webhook.teams", view.DeliveryHistory[1].Destination)
		assert.Equal(t, "exhausted", view.DeliveryHistory[1].Status)
	})

	t.Run("rejects invalid limit without changing the database", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := store.ApplyManualBan(ctx, "192.0.2.13", now.Add(time.Hour), "test", now, []string{"webhook.receiver"})
		require.NoError(t, err)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.ErrorContains(t, store.Finish(ctx, *job, errors.New("unavailable"), 0, now), "max-attempts")

		view, err := store.GetDecision(ctx, record.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, view.DeliveryHistory, 1)
		assert.Empty(t, view.DeliveryHistory[0].Attempts)

		err = store.ReconcileAttemptLimit(ctx, "webhook.receiver", 0)
		require.ErrorContains(t, err, "max-attempts")
	})

	t.Run("rejects unknown destination", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"), "webhook.receiver")
		t.Cleanup(func() { require.NoError(t, store.Close()) })

		err := store.ReconcileAttemptLimit(t.Context(), "webhook.unknown", 2)

		require.ErrorContains(t, err, `destination "webhook.unknown" is not configured`)
	})
}
