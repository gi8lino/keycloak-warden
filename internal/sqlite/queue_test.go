package sqlite_test

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/pkg/model"
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
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), retry.DefaultMaxAttempts, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
	pending, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, second.Decision, pending.Decision)
	record, err := store.GetDecision(ctx, first.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, record.DeliveryHistory, 2)
	old := record.DeliveryHistory[1]
	assert.Equal(t, model.DeliverySuperseded, old.Status)
	assert.Equal(t, second.Decision.Revision, old.SupersededByRevision)
	require.Len(t, old.Attempts, 1)
	assert.Equal(t, model.AttemptFailed, old.Attempts[0].Outcome)
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
	require.NoError(t, store.Finish(ctx, *job, errors.New("not_authed"), retry.DefaultMaxAttempts, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
	retryView, err := store.GetDecision(ctx, record.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, retryView.DeliveryHistory, 1)
	delivery := retryView.DeliveryHistory[0]
	assert.Equal(t, model.DeliveryRetrying, delivery.Status)
	require.NotNil(t, delivery.NextAttemptAt)
	next := *delivery.NextAttemptAt
	require.NoError(t, store.Finish(ctx, *job, nil, retry.DefaultMaxAttempts, next, 0))
	require.NoError(t, store.Close())

	reopened, _ := openStore(t, path, "slack")
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	result, err := reopened.GetDecision(ctx, record.Decision.ID, next)
	require.NoError(t, err)
	require.Len(t, result.DeliveryHistory, 1)
	delivery = result.DeliveryHistory[0]
	assert.Equal(t, model.DeliveryDelivered, delivery.Status)
	assert.Equal(t, model.DecisionBanned, delivery.DesiredState)
	assert.Equal(t, &next, delivery.AcknowledgedAt)
	assert.Nil(t, delivery.NextAttemptAt)
	require.Len(t, delivery.Attempts, 2)
	assert.EqualValues(t, 1, delivery.Attempts[0].Number)
	assert.Equal(t, now, delivery.Attempts[0].At)
	assert.Equal(t, "not_authed", delivery.Attempts[0].Error)
	assert.EqualValues(t, 2, delivery.Attempts[1].Number)
	assert.Equal(t, model.AttemptSucceeded, delivery.Attempts[1].Outcome)
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

		err = store.Finish(ctx, *job, errors.New("failure"), retry.DefaultMaxAttempts, now, 0)
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
		require.NoError(t, store.Finish(ctx, *job, errors.New("failure"), retry.DefaultMaxAttempts, now, delay))

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
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), 10, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))

	// A new IP shares the pause, even if the worker restarts.
	for _, id := range []string{"three", "four"} {
		event := failed(id)
		event.User.IP = "203.0.113.2"
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
		require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), 10, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
	}
	now = now.Add(5 * time.Minute)
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, model.DecisionUnbanned, job.Decision.State)
	require.NoError(t, store.Finish(ctx, *job, nil, 10, now, 0))

	// The other pending release gets a fresh first retry after the destination recovers.
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), 10, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
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
			err := bans.ExtendSource(ctx, tx, "203.0.113.2", model.Source{
				Kind: model.SourceAutomatic, ExpiresAt: now.Add(time.Hour),
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
		require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), retry.DefaultMaxAttempts, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
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
		assert.Equal(t, model.DecisionUnbanned, job.Decision.State)
		require.NoError(t, store.Finish(ctx, *job, nil, retry.DefaultMaxAttempts, due, 0))
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
		require.NoError(t, store.Finish(ctx, *job, errors.New("unavailable"), retry.DefaultMaxAttempts, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
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
	assert.Equal(t, model.DeliveryExhausted, delivery.Status)
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
	require.NoError(t, store.Finish(ctx, *job, errors.New("still unavailable"), 4, now, retry.DefaultRetryPolicy().NextDelay(job.PreviousDelay)))
	_, err = bans.ReleaseAllSources(ctx, store, record.Decision.ID, now, []string{"receiver"})
	require.NoError(t, err)
	job, err = store.Next(ctx, now.Add(5*time.Minute))
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, model.DecisionUnbanned, job.Decision.State)
}

// TestFinishIgnoresStaleDeliverySuccess verifies that a completed older call
// cannot acknowledge a newer revision or rewrite its superseded history.
func TestFinishIgnoresStaleDeliverySuccess(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, _ := openStore(t, filepath.Join(t.TempDir(), "stale-success.db"), "edge")
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := bans.ApplyManualBan(ctx, store, "203.0.113.67", now.Add(time.Hour), "initial", now, []string{"edge"})
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)

	second, err := bans.ApplyManualBan(ctx, store, "203.0.113.67", now.Add(2*time.Hour), "extended", now, []string{"edge"})
	require.NoError(t, err)
	require.Greater(t, second.Decision.Revision, first.Decision.Revision)

	require.NoError(t, store.Finish(ctx, *job, nil, retry.DefaultMaxAttempts, now, 0))

	next, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, next)
	assert.Equal(t, second.Decision, next.Decision)

	record, err := store.GetDecision(ctx, first.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, record.DeliveryHistory, 2)
	assert.Equal(t, model.DeliveryPending, record.DeliveryHistory[0].Status)
	assert.Equal(t, model.DeliverySuperseded, record.DeliveryHistory[1].Status)
	require.Len(t, record.DeliveryHistory[1].Attempts, 1)
	assert.Equal(t, model.AttemptSucceeded, record.DeliveryHistory[1].Attempts[0].Outcome)
}

// TestRapidBanReleaseBanWithInflightDelivery ensures a late completion cannot
// override the newest desired ban after two intervening state transitions.
func TestRapidBanReleaseBanWithInflightDelivery(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, _ := openStore(t, filepath.Join(t.TempDir(), "transitions.db"), "edge")
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := bans.ApplyManualBan(ctx, store, "203.0.113.68", now.Add(time.Hour), "initial", now, []string{"edge"})
	require.NoError(t, err)
	inFlight, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, inFlight)

	released, err := bans.ReleaseAllSources(ctx, store, first.Decision.ID, now.Add(time.Second), []string{"edge"})
	require.NoError(t, err)
	assert.Equal(t, model.DecisionUnbanned, released.Decision.State)

	newBan, err := bans.ApplyManualBan(ctx, store, "203.0.113.68", now.Add(2*time.Hour), "second", now.Add(2*time.Second), []string{"edge"})
	require.NoError(t, err)
	assert.Equal(t, model.DecisionBanned, newBan.Decision.State)
	assert.Greater(t, newBan.Decision.Revision, released.Decision.Revision)

	require.NoError(t, store.Finish(ctx, *inFlight, nil, retry.DefaultMaxAttempts, now.Add(3*time.Second), 0))

	next, err := store.Next(ctx, now.Add(3*time.Second))
	require.NoError(t, err)
	require.NotNil(t, next)
	assert.Equal(t, newBan.Decision.Revision, next.Decision.Revision)
	assert.Equal(t, model.DecisionBanned, next.Decision.State)

	record, err := store.GetDecision(ctx, first.Decision.ID, now.Add(3*time.Second))
	require.NoError(t, err)
	require.Len(t, record.DeliveryHistory, 3)
	assert.Equal(t, model.DeliveryPending, record.DeliveryHistory[0].Status)
	assert.Equal(t, model.DeliverySuperseded, record.DeliveryHistory[1].Status)
	assert.Equal(t, model.DeliverySuperseded, record.DeliveryHistory[2].Status)
	assert.Equal(t, model.AttemptSucceeded, record.DeliveryHistory[2].Attempts[0].Outcome)
}

// TestDeliveryHistoryPaging checks direct one-based SQLite paging without
// deleting recorded audit history.
func TestDeliveryHistoryPaging(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, _ := openStore(t, filepath.Join(t.TempDir(), "pages.db"), "edge", "notifications")
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)

	var id string
	for i := 1; i <= 20; i++ {
		ban, err := bans.ApplyManualBan(ctx, store, "203.0.113.69", now.Add(time.Duration(i)*time.Hour), "extended", now, []string{"edge", "notifications"})
		require.NoError(t, err)
		id = ban.Decision.ID
	}

	// Request page 3 first to prove no earlier page or cursor is required.
	third, err := store.GetDecisionPage(ctx, id, now, testHistoryPage(t, 3, 0))
	require.NoError(t, err)
	assert.Equal(t, 3, third.HistoryPage)
	assert.Zero(t, third.HistoryNextPage)
	require.Len(t, third.DeliveryHistory, 8)
	assert.EqualValues(t, 4, third.DeliveryHistory[0].Revision)
	assert.EqualValues(t, 1, third.DeliveryHistory[7].Revision)

	first, err := store.GetDecisionPage(ctx, id, now, testHistoryPage(t, 1, 0))
	require.NoError(t, err)
	assert.Equal(t, 2, first.HistoryNextPage)
	require.Len(t, first.DeliveryHistory, bans.HistoryPageSize)

	_, err = bans.ApplyManualBan(ctx, store, "203.0.113.69", now.Add(21*time.Hour), "new revision between pages", now, []string{"edge", "notifications"})
	require.NoError(t, err)
	second, err := store.GetDecisionPage(ctx, id, now, testHistoryPage(t, 2, first.Decision.Revision))
	require.NoError(t, err)
	assert.Equal(t, 3, second.HistoryNextPage)
	require.Len(t, second.DeliveryHistory, bans.HistoryPageSize)

	seen := make(map[string]bool)
	for _, page := range []model.Record{first, second, third} {
		for _, item := range page.DeliveryHistory {
			key := fmt.Sprintf("%d/%s", item.Revision, item.Destination)
			assert.False(t, seen[key], "history must not repeat entries across pages")
			seen[key] = true
		}
	}
	assert.Len(t, seen, 40)

	beyond, err := store.GetDecisionPage(ctx, id, now, testHistoryPage(t, 100, 0))
	require.NoError(t, err)
	assert.Equal(t, 100, beyond.HistoryPage)
	assert.Empty(t, beyond.DeliveryHistory)
	assert.Zero(t, beyond.HistoryNextPage)
}

// TestDeliveryAttemptHistoryBounded checks that large error messages and long
// attempt sequences do not make the inspection response unbounded.
func TestDeliveryAttemptHistoryBounded(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, _ := openStore(t, filepath.Join(t.TempDir(), "attempt-page.db"), "edge")
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)

	record, err := bans.ApplyManualBan(ctx, store, "203.0.113.70", now.Add(time.Hour), "incident", now, []string{"edge"})
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)

	for range 20 {
		require.NoError(t, store.Finish(ctx, *job, errors.New(strings.Repeat("x", 2048)), 100, now, time.Second))
	}

	view, err := store.GetDecision(ctx, record.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, view.DeliveryHistory, 1)
	assert.True(t, view.DeliveryHistory[0].AttemptsTruncated)
	require.Len(t, view.DeliveryHistory[0].Attempts, 16)
	assert.EqualValues(t, 5, view.DeliveryHistory[0].Attempts[0].Number)
	assert.Len(t, view.DeliveryHistory[0].Attempts[0].Error, 512)
}

// testHistoryPage constructs application-validated bounds for storage tests.
func testHistoryPage(t *testing.T, number int, throughRevision int64) bans.HistoryPage {
	t.Helper()
	page, err := bans.NewHistoryPage(number, throughRevision)
	require.NoError(t, err)
	return page
}
