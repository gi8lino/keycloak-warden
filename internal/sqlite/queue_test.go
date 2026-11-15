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
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// TestFinishIgnoresStaleDeliveryFailure ensures old delivery failures cannot delay new revisions.
func TestFinishIgnoresStaleDeliveryFailure(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "test.db"), "edge")
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(time.Hour), "investigation", now, []string{"edge"})
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, first.Decision.Revision, job.Decision.Revision)

	// The desired state changes while the old revision is in flight.
	second, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(2*time.Hour), "extended", now, []string{"edge"})
	require.NoError(t, err)
	require.Greater(t, second.Decision.Revision, first.Decision.Revision)

	// A failed attempt against revision 1 must not postpone revision 2.
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(job.PreviousDelay)))
	pending, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, second.Decision, pending.Decision)
	record, err := store.GetDecision(ctx, first.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, record.DeliveryHistory, 2)
	old := record.DeliveryHistory[1]
	assert.Equal(t, "superseded", old.Status)
	assert.Equal(t, second.Decision.Revision, old.SupersededByRevision)
	require.Len(t, old.Attempts, 1)
	assert.Equal(t, "failed", old.Attempts[0].Outcome)
	assert.Nil(t, old.NextAttemptAt)
}

func TestDeliveryAttemptsSurviveRetryAndRestart(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "history.db")
	store, _ := openStore(t, path, "slack")
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, err := bans.ApplyManualBan(ctx, store, "192.0.2.5", now.Add(time.Hour), "test", now, []string{"slack"})
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, errors.New("not_authed"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(job.PreviousDelay)))
	retry, err := store.GetDecision(ctx, record.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, retry.DeliveryHistory, 1)
	delivery := retry.DeliveryHistory[0]
	assert.Equal(t, "retrying", delivery.Status)
	require.NotNil(t, delivery.NextAttemptAt)
	next := *delivery.NextAttemptAt
	require.NoError(t, store.Finish(ctx, *job, nil, actions.DefaultMaxAttempts, next, 0))
	require.NoError(t, store.Close())

	reopened, _ := openStore(t, path, "slack")
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	result, err := reopened.GetDecision(ctx, record.Decision.ID, next)
	require.NoError(t, err)
	require.Len(t, result.DeliveryHistory, 1)
	delivery = result.DeliveryHistory[0]
	assert.Equal(t, "delivered", delivery.Status)
	assert.Equal(t, "banned", delivery.DesiredState)
	assert.Equal(t, &next, delivery.AcknowledgedAt)
	assert.Nil(t, delivery.NextAttemptAt)
	require.Len(t, delivery.Attempts, 2)
	assert.EqualValues(t, 1, delivery.Attempts[0].Number)
	assert.Equal(t, now, delivery.Attempts[0].At)
	assert.Equal(t, "not_authed", delivery.Attempts[0].Error)
	assert.EqualValues(t, 2, delivery.Attempts[1].Number)
	assert.Equal(t, "succeeded", delivery.Attempts[1].Outcome)
	assert.Empty(t, delivery.Attempts[1].Error)
}

func TestFinishRetryDelay(t *testing.T) {
	t.Parallel()

	t.Run("rejects nonpositive delay without an attempt", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "retry.db")
		store, _ := openStore(t, path, "edge")
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		db, err := sql.Open("sqlite", path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, db.Close()) })
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = bans.ApplyManualBan(ctx, store, "203.0.113.91", now.Add(time.Hour), "incident", now, []string{"edge"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)

		err = store.Finish(ctx, *job, errors.New("failure"), actions.DefaultMaxAttempts, now, 0)
		require.ErrorContains(t, err, "retry delay")

		var attempts int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM delivery_attempts").Scan(&attempts))
		assert.Zero(t, attempts)
	})

	t.Run("persists an application-supplied delay", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "retry.db")
		store, _ := openStore(t, path, "edge")
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		db, err := sql.Open("sqlite", path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, db.Close()) })
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = bans.ApplyManualBan(ctx, store, "203.0.113.92", now.Add(time.Hour), "incident", now, []string{"edge"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)

		delay := 37 * time.Second
		require.NoError(t, store.Finish(ctx, *job, errors.New("failure"), actions.DefaultMaxAttempts, now, delay))

		var millis, retryAt int64
		require.NoError(t, db.QueryRowContext(ctx,
			"SELECT delay_ms, retry_at FROM destination_backoff WHERE destination = ?", "edge",
		).Scan(&millis, &retryAt))
		assert.Equal(t, delay.Milliseconds(), millis)
		assert.Equal(t, now.Add(delay).UnixMilli(), retryAt)
		next, err := store.Next(ctx, now.Add(delay))
		require.NoError(t, err)
		require.NotNil(t, next)
		assert.Equal(t, delay, next.PreviousDelay)
	})
}

func TestDestinationBackoff(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	store, processor := openStore(t, path, "edge")
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err := processDecision(processor, ctx, failed("one"), now)
	require.NoError(t, err)
	_, err = processDecision(processor, ctx, failed("two"), now)
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), 10, now, actions.NextRetryDelay(job.PreviousDelay)))

	// A new IP shares the pause, even if the worker restarts.
	for _, id := range []string{"three", "four"} {
		event := failed(id)
		event.IP = "203.0.113.2"
		_, err = processDecision(processor, ctx, event, now)
		require.NoError(t, err)
	}
	require.NoError(t, store.Close())
	store, _ = openStore(t, path, "edge")
	require.NoError(t, store.ReconcileAttemptLimit(ctx, "edge", 10))

	for _, seconds := range []int{10, 20, 40, 80, 160, 300, 300} {
		due := now.Add(time.Duration(seconds) * time.Second)
		_, err = bans.ExpireSources(ctx, store, due.Add(-time.Millisecond), []string{"edge"})
		require.NoError(t, err)
		pending, err := store.Next(ctx, due.Add(-time.Millisecond))
		require.NoError(t, err)
		require.Nil(t, pending)
		now = due
		job, err = store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		if seconds == 10 {
			assert.Equal(t, "203.0.113.2", job.Decision.IP)
		}
		require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), 10, now, actions.NextRetryDelay(job.PreviousDelay)))
	}
	now = now.Add(5 * time.Minute)
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
	require.NoError(t, store.Finish(ctx, *job, nil, 10, now, 0))

	// The other pending release gets a fresh first retry after the destination recovers.
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), 10, now, actions.NextRetryDelay(job.PreviousDelay)))
	pending, err := store.Next(ctx, now.Add(10*time.Second))
	require.NoError(t, err)
	require.NotNil(t, pending)
}

func TestWorkerSchedule(t *testing.T) {
	t.Parallel()

	t.Run("only committed decisions wake the worker", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		now := time.Now()
		store, processor := openStore(t, filepath.Join(t.TempDir(), "state.db"), "receiver")
		defer store.Close() //nolint:errcheck
		_, err := processDecision(processor, ctx, failed("one"), now)
		require.NoError(t, err)
		rollback := errors.New("rollback")
		err = store.TransactObservation(ctx, func(tx ingestion.Transaction) error {
			err := bans.ExtendSource(ctx, tx, "203.0.113.2", bans.Source{
				Kind: bans.SourceAutomatic, ExpiresAt: now.Add(time.Hour),
			})
			if err == nil {
				_, _, err = bans.ReconcileDecision(ctx, tx, "203.0.113.2", now, []string{"receiver"})
			}
			require.NoError(t, err)
			return rollback
		})
		require.ErrorIs(t, err, rollback)
		select {
		case <-store.Changes():
			require.FailNow(t, "unexpected wake before decision commit")
		default:
		}
		_, err = processDecision(processor, ctx, failed("two"), now)
		require.NoError(t, err)
		select {
		case <-store.Changes():
		default:
			require.FailNow(t, "missing wake after decision commit")
		}
	})

	t.Run("restart schedules the earlier of source expiry and destination retry", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "state.db")
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, _ := openStore(t, path, "receiver")
		_, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(8*time.Second), "test", now, []string{"receiver"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(job.PreviousDelay)))
		require.NoError(t, store.Close())
		store, _ = openStore(t, path, "receiver")
		defer store.Close() //nolint:errcheck
		due, err := store.NextDeadline(ctx)
		require.NoError(t, err)
		require.True(t, now.Add(8*time.Second).Equal(due))
		_, err = bans.ExpireSources(ctx, store, due, []string{"receiver"})
		require.NoError(t, err)
		due, err = store.NextDeadline(ctx)
		require.NoError(t, err)
		require.True(t, now.Add(10*time.Second).Equal(due))
		job, err = store.Next(ctx, due)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
		require.NoError(t, store.Finish(ctx, *job, nil, actions.DefaultMaxAttempts, due, 0))
		due, err = store.NextDeadline(ctx)
		require.NoError(t, err)
		assert.True(t, due.IsZero())
	})
}

func TestAttemptBudget(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "budget.db")
	store, _ := openStore(t, path, "receiver")
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, err := bans.ApplyManualBan(ctx, store, "192.0.2.1", now.Add(time.Hour), "test", now, []string{"receiver"})
	require.NoError(t, err)
	for range 3 {
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(job.PreviousDelay)))
		now = now.Add(time.Minute)
	}
	require.NoError(t, store.Close())

	store, _ = openStore(t, path, "receiver")
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	assert.Nil(t, job)
	inspected, err := store.GetDecision(ctx, record.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, inspected.DeliveryHistory, 1)
	delivery := inspected.DeliveryHistory[0]
	assert.Equal(t, "exhausted", delivery.Status)
	assert.Nil(t, delivery.NextAttemptAt)
	assert.Len(t, delivery.Attempts, 3)
	due, err := store.NextDeadline(ctx)
	require.NoError(t, err)
	assert.Equal(t, record.Decision.ExpiresAt, due.UTC())
	require.NoError(t, store.Close())

	store, _ = openStore(t, path, "receiver")
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	require.NoError(t, store.ReconcileAttemptLimit(ctx, "receiver", 4))
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, errors.New("still unavailable"), 4, now, actions.NextRetryDelay(job.PreviousDelay)))
	_, err = bans.ReleaseAllSources(ctx, store, record.Decision.ID, now, []string{"receiver"})
	require.NoError(t, err)
	job, err = store.Next(ctx, now.Add(5*time.Minute))
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
}
