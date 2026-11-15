package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// openStore constructs an isolated store and matching application ingestion use case.
func openStore(t *testing.T, path string, targets ...string) (*sqlite.Store, *ingestion.Service) {
	t.Helper()

	rule := detection.Rule{
		Threshold: 2,
		Window:    time.Minute,
		Ban:       2 * time.Minute,
	}
	store, err := sqlite.Open(path)
	require.NoError(t, err)

	require.NoError(t, store.ValidateTargets(t.Context(), targets))

	processor, err := ingestion.New(store, rule, targets)
	require.NoError(t, err)

	return store, processor
}

// processDecision extracts a changed decision from an ingestion outcome for storage tests.
func processDecision(processor *ingestion.Service, ctx context.Context, event events.Envelope, now time.Time) (*decisions.Decision, error) {
	result, err := processor.Process(ctx, event, now)
	return result.Decision, err
}

// failed constructs a distinct Keycloak failed login from one stable client address.
func failed(id string) events.Envelope {
	return events.Envelope{
		ID:        id,
		Source:    "keycloak",
		Kind:      "LOGIN_ERROR",
		Version:   1,
		Timestamp: time.Date(2026, time.November, 5, 15, 0, 0, 0, time.UTC),
		IP:        "203.0.113.1",
	}
}

func TestStoreTransact(t *testing.T) {
	t.Parallel()

	t.Run("duplicates and nonmatching events never reach threshold", func(t *testing.T) {
		t.Parallel()

		store, processor := openStore(t, filepath.Join(t.TempDir(), "test.db"))
		defer store.Close() // nolint:errcheck
		now := time.Now()
		ok := failed("success")
		ok.Kind = "LOGIN"
		noIP := failed("missing")
		noIP.IP = ""
		decision, err := processDecision(processor, t.Context(), failed("same"), now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), failed("same"), now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), ok, now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), noIP, now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), failed("outside-window"), now.Add(time.Minute))

		require.NoError(t, err)
		assert.Nil(t, decision)
	})

	t.Run("concurrent replays count once", func(t *testing.T) {
		t.Parallel()

		store, processor := openStore(t, filepath.Join(t.TempDir(), "test.db"))
		defer store.Close() // nolint:errcheck
		var wg sync.WaitGroup
		now := time.Now()
		for range 12 {
			wg.Go(func() {
				decision, err := processDecision(processor, context.Background(), failed("repeat"), now)

				assert.NoError(t, err)
				assert.Nil(t, decision)
			})
		}
		wg.Wait()
		decision, err := processDecision(processor, t.Context(), failed("next"), now)

		require.NoError(t, err)
		require.NotNil(t, decision)
	})
}

// TestStoreTransactionLifecycle verifies both application interfaces use the same atomic lifecycle.
func TestStoreTransactionLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("observation transactions can persist failures and ban sources atomically", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "observation.db"))
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		ip := "203.0.113.92"
		event := events.Event{
			ID:     "observation-1",
			Source: "keycloak",
			IP:     netip.MustParseAddr(ip),
		}

		err := store.Transact(ctx, func(tx ingestion.Transaction) error {
			inserted, err := tx.RecordFailure(ctx, event, now)
			if err != nil {
				return err
			}
			assert.True(t, inserted)

			if err := tx.EnsureDecision(ctx, ip); err != nil {
				return err
			}
			return tx.PutSource(ctx, ip, bans.Source{
				Kind:      bans.SourceAutomatic,
				ExpiresAt: now.Add(time.Hour),
			})
		})
		require.NoError(t, err)

		select {
		case <-store.Changes():
		default:
			require.FailNow(t, "committed source change must notify the worker")
		}

		err = store.Transact(ctx, func(tx ingestion.Transaction) error {
			count, err := tx.CountFailures(ctx, ip, now.Add(-time.Minute))
			if err != nil {
				return err
			}
			assert.Equal(t, 1, count)
			return nil
		})
		require.NoError(t, err)

		select {
		case <-store.Changes():
			require.FailNow(t, "read-only observation transaction must not notify the worker")
		default:
		}
	})

	t.Run("ban transactions roll back source mutations without notification", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "ban.db"))
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		ip := "203.0.113.93"
		rollback := errors.New("injected rollback")

		err := store.TransactBan(ctx, func(tx bans.MutationTransaction) error {
			if err := tx.EnsureDecision(ctx, ip); err != nil {
				return err
			}
			if err := tx.PutSource(ctx, ip, bans.Source{
				Kind:      bans.SourceManual,
				ExpiresAt: now.Add(time.Hour),
				Reason:    "investigation",
			}); err != nil {
				return err
			}
			return rollback
		})
		require.ErrorIs(t, err, rollback)

		err = store.TransactBan(ctx, func(tx bans.MutationTransaction) error {
			_, err := tx.Decision(ctx, ip)
			return err
		})
		require.ErrorIs(t, err, sql.ErrNoRows)

		select {
		case <-store.Changes():
			require.FailNow(t, "rolled-back ban transaction must not notify the worker")
		default:
		}
	})
}

func TestOpen(t *testing.T) {
	t.Parallel()

	t.Run("restart retains work and expiry releases each destination independently", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "test.db")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, processor := openStore(t, path, "a", "b")
		_, err := processDecision(processor, ctx, failed("one"), now)

		require.NoError(t, err)
		decision, err := processDecision(processor, ctx, failed("two"), now)

		require.NoError(t, err)
		require.NotNil(t, decision)
		require.NoError(t, store.Close())

		store, processor = openStore(t, path, "a", "b")
		defer store.Close() // nolint:errcheck
		a, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, a)
		assert.Equal(t, "a", a.Destination)
		assert.Zero(t, a.PreviousDelay)
		require.NoError(t, store.Finish(ctx, *a, errors.New("provider failure"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(a.PreviousDelay)))
		b, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, b)
		assert.Equal(t, "b", b.Destination)
		require.NoError(t, store.Finish(ctx, *b, nil, actions.DefaultMaxAttempts, now, 0))
		retry, err := store.Next(ctx, now.Add(11*time.Second))

		require.NoError(t, err)
		require.NotNil(t, retry)
		assert.Equal(t, a.Decision, retry.Decision)
		assert.Equal(t, a.Destination, retry.Destination)
		assert.Equal(t, actions.FirstRetryDelay, retry.PreviousDelay)

		later := now.Add(time.Second)
		extended, err := processDecision(processor, ctx, failed("three"), later)

		require.NoError(t, err)
		require.NotNil(t, extended)
		assert.Equal(t, decision.ID, extended.ID)
		assert.Equal(t, int64(2), extended.Revision)
		require.NoError(t, store.Finish(ctx, *a, nil, actions.DefaultMaxAttempts, later, 0))
		pending, err := store.Next(ctx, later)

		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, *extended, pending.Decision)
		active, err := store.ListActive(ctx, later)

		require.NoError(t, err)
		require.Len(t, active, 1)
		assert.Equal(t, extended, &active[0].Decision)
		view, err := store.GetDecision(ctx, extended.ID, later)

		require.NoError(t, err)
		assert.Equal(t, *extended, view.Decision)
		assert.Equal(
			t,
			[]decisions.Acknowledgement{{Destination: "a", Revision: 1}, {Destination: "b", Revision: 1}},
			view.Deliveries,
		)

		now = extended.ExpiresAt

		_, err = bans.ExpireSources(ctx, store, now, []string{"a", "b"})
		require.NoError(t, err)
		release, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, release)
		assert.Equal(t, "a", release.Destination)
		assert.Equal(t, decisions.StateUnbanned, release.Decision.State)
		assert.Equal(t, int64(3), release.Decision.Revision)
		require.NoError(t, store.Finish(ctx, *release, nil, actions.DefaultMaxAttempts, now, 0))
		release, err = store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, release)
		assert.Equal(t, "b", release.Destination)
		assert.Equal(t, decisions.StateUnbanned, release.Decision.State)
		assert.Equal(t, int64(3), release.Decision.Revision)
		require.NoError(t, store.Finish(ctx, *release, nil, actions.DefaultMaxAttempts, now, 0))
		active, err = store.ListActive(ctx, now)

		require.NoError(t, err)
		assert.Empty(t, active)
	})
}

func TestOptimize(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "optimize.db"))
	require.NoError(t, store.Optimize(t.Context()))
	require.NoError(t, store.Close())
	require.Error(t, store.Optimize(t.Context()), "optimization should not succeed on a closed store")
}

// TestAdditionalFailureDoesNotReviseUnchangedBan ensures observation counts do not trigger delivery revisions.
func TestAdditionalFailureDoesNotReviseUnchangedBan(t *testing.T) {
	t.Parallel()

	store, processor := openStore(t, filepath.Join(t.TempDir(), "state.db"), "receiver")
	defer store.Close() //nolint:errcheck
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err := processDecision(processor, ctx, failed("first"), now)
	require.NoError(t, err)
	original, err := processDecision(processor, ctx, failed("second"), now)
	require.NoError(t, err)
	require.NotNil(t, original)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, nil, actions.DefaultMaxAttempts, now, 0))

	latest, err := processor.Process(ctx, failed("third"), now)
	require.NoError(t, err)
	assert.Equal(t, ingestion.OutcomeUnchanged, latest.Outcome)
	assert.Nil(t, latest.Decision, "an extra observation must not be reported as a new decision")
	record, err := store.GetDecision(ctx, original.ID, now)
	require.NoError(t, err)
	assert.Equal(t, *original, record.Decision)
	next, err := store.Next(ctx, now)
	require.NoError(t, err)
	assert.Nil(t, next, "an unchanged ban must not be delivered again")
}

func TestOpenValidation(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing database directory", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "missing-directory", "state.db")
		store, err := sqlite.Open(path)
		require.Error(t, err)
		assert.Nil(t, store)
	})
}

func TestStoreClosedErrors(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, store.Close())

	assert.Error(t, store.Ping(t.Context()))
	assert.Error(t, store.Prune(t.Context(), time.Now()))
	_, err := store.Next(t.Context(), time.Now())
	assert.Error(t, err)
	_, err = store.NextDeadline(t.Context())
	assert.Error(t, err)
	_, err = bans.ExpireSources(t.Context(), store, time.Now(), nil)
	assert.Error(t, err)
	assert.Error(t, store.Transact(t.Context(), func(ingestion.Transaction) error {
		return errors.New("should not be invoked")
	}))
}

func TestValidateTargets(t *testing.T) {
	t.Parallel()

	t.Run("rejects removal with an active ban", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "warden.db")
		store, err := sqlite.Open(path)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := bans.ApplyManualBan(ctx, store, "203.0.113.81", now.Add(time.Hour), "incident", now, []string{"old"})
		require.NoError(t, err)
		require.NoError(t, store.Close())

		reopened, err := sqlite.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })

		require.ErrorContains(t, reopened.ValidateTargets(ctx, []string{"replacement"}), `destination "old" has managed decisions`)
		require.NoError(t, reopened.ValidateTargets(ctx, []string{"old"}))

		pending, err := reopened.Next(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, created.Decision.ID, pending.Decision.ID)
	})

	t.Run("rejects removal with an unacknowledged release", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "warden.db")
		store, err := sqlite.Open(path)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := bans.ApplyManualBan(ctx, store, "203.0.113.81", now.Add(time.Hour), "incident", now, []string{"old"})
		require.NoError(t, err)
		_, err = bans.ReleaseAllSources(ctx, store, created.Decision.ID, now.Add(time.Second), []string{"old"})
		require.NoError(t, err)
		require.NoError(t, store.Close())

		reopened, err := sqlite.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })

		require.ErrorContains(t, reopened.ValidateTargets(ctx, []string{"replacement"}), `destination "old" has managed decisions`)
		require.NoError(t, reopened.ValidateTargets(ctx, []string{"old"}))

		pending, err := reopened.Next(ctx, now.Add(2*time.Second))
		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, created.Decision.ID, pending.Decision.ID)
	})
}
