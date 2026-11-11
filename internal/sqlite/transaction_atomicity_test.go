package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

// openAtomicityStore creates a disposable database for injected SQLite failures.
func openAtomicityStore(t *testing.T, targets ...string) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "warden.db"), detection.Rule{
		Threshold: 2,
		Window:    time.Minute,
		Ban:       2 * time.Minute,
	}, targets)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store
}

func TestApplyManualBanRollback(t *testing.T) {
	t.Parallel()

	store := openAtomicityStore(t, "edge")
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	ip := "203.0.113.41"

	// Fail after the decision and manual source have been inserted, but before
	// reconciliation can commit the effective state and pending deliveries.
	_, err := store.db.Exec(`
CREATE TRIGGER reject_reconciliation
BEFORE UPDATE OF revision ON decisions
BEGIN
    SELECT RAISE(ABORT, 'injected reconciliation failure');
END
`)
	require.NoError(t, err)

	_, err = store.ApplyManualBan(ctx, ip, now.Add(time.Hour), "investigation", now)
	require.ErrorContains(t, err, "injected reconciliation failure")

	var decisionsCount, sourcesCount, deliveriesCount int
	require.NoError(t, store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM decisions WHERE ip = ?", ip).Scan(&decisionsCount))
	require.NoError(t, store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ban_sources WHERE ip = ?", ip).Scan(&sourcesCount))
	require.NoError(t, store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM deliveries WHERE ip = ?", ip).Scan(&deliveriesCount))
	assert.Zero(t, decisionsCount)
	assert.Zero(t, sourcesCount)
	assert.Zero(t, deliveriesCount)
	select {
	case <-store.Changes():
		t.Fatal("failed transaction must not notify the delivery worker")
	default:
	}

	_, err = store.db.Exec("DROP TRIGGER reject_reconciliation")
	require.NoError(t, err)
	created, err := store.ApplyManualBan(ctx, ip, now.Add(time.Hour), "investigation", now)
	require.NoError(t, err)
	assert.Equal(t, decisions.StateBanned, created.Decision.State)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, created.Decision, job.Decision)
}

func TestReleaseAllSourcesRollback(t *testing.T) {
	t.Parallel()

	store := openAtomicityStore(t, "edge")
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	created, err := store.ApplyManualBan(ctx, "203.0.113.42", now.Add(time.Hour), "investigation", now)
	require.NoError(t, err)
	<-store.Changes()

	_, err = store.db.Exec(`
CREATE TRIGGER reject_release
BEFORE UPDATE OF revision ON decisions
BEGIN
    SELECT RAISE(ABORT, 'injected release failure');
END
`)
	require.NoError(t, err)

	_, err = store.ReleaseAllSources(ctx, created.Decision.ID, now.Add(time.Second))
	require.ErrorContains(t, err, "injected release failure")

	unchanged, err := store.GetDecision(ctx, created.Decision.ID, now)
	require.NoError(t, err)
	assert.Equal(t, created, unchanged)
	var generation int64
	require.NoError(t, store.db.QueryRowContext(ctx,
		"SELECT failure_generation FROM decisions WHERE ip = ?", created.Decision.IP,
	).Scan(&generation))
	assert.Zero(t, generation, "rollback must restore the previous observation generation")
	select {
	case <-store.Changes():
		t.Fatal("failed release must not notify the delivery worker")
	default:
	}

	_, err = store.db.Exec("DROP TRIGGER reject_release")
	require.NoError(t, err)
	released, err := store.ReleaseAllSources(ctx, created.Decision.ID, now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, decisions.StateUnbanned, released.Decision.State)
	require.NoError(t, store.db.QueryRowContext(ctx,
		"SELECT failure_generation FROM decisions WHERE ip = ?", created.Decision.IP,
	).Scan(&generation))
	assert.EqualValues(t, 1, generation)
}

func TestMaintainRollbackAcrossAddresses(t *testing.T) {
	t.Parallel()

	store := openAtomicityStore(t, "edge")
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	first, err := store.ApplyManualBan(ctx, "203.0.113.51", now.Add(10*time.Second), "first", now)
	require.NoError(t, err)
	second, err := store.ApplyManualBan(ctx, "203.0.113.52", now.Add(10*time.Second), "second", now)
	require.NoError(t, err)
	remaining, err := store.ApplyManualBan(ctx, "203.0.113.53", now.Add(time.Hour), "longer", now)
	require.NoError(t, err)

	_, err = store.db.Exec(`
CREATE TRIGGER reject_second_expiry
BEFORE UPDATE OF revision ON decisions
WHEN NEW.ip = '203.0.113.52'
BEGIN
    SELECT RAISE(ABORT, 'injected expiry failure');
END
`)
	require.NoError(t, err)

	_, err = store.Maintain(ctx, now.Add(10*time.Second))
	require.ErrorContains(t, err, "injected expiry failure")
	for _, original := range []decisions.Decision{first.Decision, second.Decision} {
		recorded, readErr := store.GetDecision(ctx, original.ID, now)
		require.NoError(t, readErr)
		assert.Equal(t, original, recorded.Decision)
		require.Len(t, recorded.Sources, 1, "expiration must roll back for every IP")
	}

	_, err = store.db.Exec("DROP TRIGGER reject_second_expiry")
	require.NoError(t, err)
	released, err := store.Maintain(ctx, now.Add(10*time.Second))
	require.NoError(t, err)
	require.Len(t, released, 2)
	assert.ElementsMatch(t, []string{first.Decision.ID, second.Decision.ID}, []string{released[0].ID, released[1].ID})
	for _, decision := range released {
		assert.Equal(t, decisions.StateUnbanned, decision.State)
	}
	current, err := store.GetDecision(ctx, remaining.Decision.ID, now.Add(10*time.Second))
	require.NoError(t, err)
	assert.Equal(t, remaining.Decision, current.Decision)
}

func TestFinishRollback(t *testing.T) {
	t.Parallel()

	t.Run("failed acknowledgement leaves revision pending", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t, "edge")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := store.ApplyManualBan(ctx, "203.0.113.61", now.Add(time.Hour), "incident", now)
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)

		_, err = store.db.Exec(`
CREATE TRIGGER reject_acknowledgement
BEFORE UPDATE OF acknowledged ON deliveries
BEGIN
    SELECT RAISE(ABORT, 'injected acknowledgement failure');
END
`)
		require.NoError(t, err)
		require.ErrorContains(t, store.Finish(ctx, *job, true, now), "injected acknowledgement failure")

		current, err := store.GetDecision(ctx, created.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, current.Deliveries, 1)
		assert.Zero(t, current.Deliveries[0].Revision)
		pending, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, job.Decision, pending.Decision)

		_, err = store.db.Exec("DROP TRIGGER reject_acknowledgement")
		require.NoError(t, err)
		require.NoError(t, store.Finish(ctx, *job, true, now))
		pending, err = store.Next(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, pending)
	})

	t.Run("failed retry scheduling leaves destination unpaused", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t, "edge")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := store.ApplyManualBan(ctx, "203.0.113.62", now.Add(time.Hour), "incident", now)
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)

		_, err = store.db.Exec(`
CREATE TRIGGER reject_retry
BEFORE UPDATE OF retry_at ON deliveries
BEGIN
    SELECT RAISE(ABORT, 'injected retry failure');
END
`)
		require.NoError(t, err)
		require.ErrorContains(t, store.Finish(ctx, *job, false, now), "injected retry failure")

		var backoffs int
		require.NoError(t, store.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM destination_backoff WHERE destination = ?", job.Destination,
		).Scan(&backoffs))
		assert.Zero(t, backoffs, "failed retry must not leave a destination-wide pause")
		pending, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, pending)

		_, err = store.db.Exec("DROP TRIGGER reject_retry")
		require.NoError(t, err)
		require.NoError(t, store.Finish(ctx, *job, false, now))
		pending, err = store.Next(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, pending)
		pending, err = store.Next(ctx, now.Add(10*time.Second))
		require.NoError(t, err)
		require.NotNil(t, pending)
	})
}
