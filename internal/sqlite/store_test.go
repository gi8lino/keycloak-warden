package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// openStore constructs an isolated store and matching application ingestion use case.
func openStore(t *testing.T, path string, targets ...string) (*sqlite.Store, *ingestion.Service) {
	t.Helper()
	rule := detection.Rule{Threshold: 2, Window: time.Minute, Ban: 2 * time.Minute}
	store, err := sqlite.Open(path, rule, targets)

	require.NoError(t, err)
	processor, err := ingestion.New(store, rule)

	require.NoError(t, err)
	return store, processor
}

// failed constructs a distinct Keycloak failed login from one stable client address.
func failed(id string) events.Envelope {
	return events.Envelope{
		ID: id, Source: "keycloak", Kind: "LOGIN_ERROR", Version: 1,
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
		decision, err := processor.Process(t.Context(), failed("same"), now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processor.Process(t.Context(), failed("same"), now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processor.Process(t.Context(), ok, now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processor.Process(t.Context(), noIP, now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processor.Process(t.Context(), failed("outside-window"), now.Add(time.Minute))

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
				decision, err := processor.Process(context.Background(), failed("repeat"), now)

				assert.NoError(t, err)
				assert.Nil(t, decision)
			})
		}
		wg.Wait()
		decision, err := processor.Process(t.Context(), failed("next"), now)

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, 2, decision.Failures)
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
		_, err := processor.Process(ctx, failed("one"), now)

		require.NoError(t, err)
		decision, err := processor.Process(ctx, failed("two"), now)

		require.NoError(t, err)
		require.NotNil(t, decision)
		require.NoError(t, store.Close())

		store, processor = openStore(t, path, "a", "b")
		defer store.Close() // nolint:errcheck
		a, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, a)
		assert.Equal(t, "a", a.Destination)
		require.NoError(t, store.Finish(ctx, *a, false, now))
		b, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, b)
		assert.Equal(t, "b", b.Destination)
		require.NoError(t, store.Finish(ctx, *b, true, now))
		retry, err := store.Next(ctx, now.Add(11*time.Second))

		require.NoError(t, err)
		assert.Equal(t, a, retry)

		later := now.Add(time.Second)
		extended, err := processor.Process(ctx, failed("three"), later)

		require.NoError(t, err)
		require.NotNil(t, extended)
		assert.Equal(t, decision.ID, extended.ID)
		assert.Equal(t, int64(2), extended.Revision)
		require.NoError(t, store.Finish(ctx, *a, true, later))
		pending, err := store.Next(ctx, later)

		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, *extended, pending.Decision)
		active, err := sqlite.ListActiveBans(ctx, path, later)

		require.NoError(t, err)
		require.Len(t, active, 1)
		assert.Equal(t, extended, &active[0].Decision)
		views, err := sqlite.InspectMany(ctx, path, []string{extended.ID})

		require.NoError(t, err)
		require.Len(t, views, 1)
		assert.Equal(t, *extended, views[0].Decision)
		assert.Equal(
			t,
			[]decisions.Acknowledgement{{Destination: "a", Revision: 1}, {Destination: "b", Revision: 1}},
			views[0].Deliveries,
		)

		now = extended.ExpiresAt

		require.NoError(t, store.Maintain(ctx, now))
		release, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, release)
		assert.Equal(t, "a", release.Destination)
		assert.Equal(t, decisions.StateUnbanned, release.Decision.State)
		assert.Equal(t, int64(3), release.Decision.Revision)
		require.NoError(t, store.Finish(ctx, *release, true, now))
		release, err = store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, release)
		assert.Equal(t, "b", release.Destination)
		assert.Equal(t, decisions.StateUnbanned, release.Decision.State)
		assert.Equal(t, int64(3), release.Decision.Revision)
		require.NoError(t, store.Finish(ctx, *release, true, now))
		active, err = sqlite.ListActiveBans(ctx, path, now)

		require.NoError(t, err)
		assert.Empty(t, active)
	})
}

func TestDestinationBackoff(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	store, processor := openStore(t, path, "edge")
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err := processor.Process(ctx, failed("one"), now)
	require.NoError(t, err)
	_, err = processor.Process(ctx, failed("two"), now)
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, false, now))

	// A new IP shares the pause, even if the worker restarts.
	for _, id := range []string{"three", "four"} {
		event := failed(id)
		event.IP = "203.0.113.2"
		_, err = processor.Process(ctx, event, now)
		require.NoError(t, err)
	}
	require.NoError(t, store.Close())
	store, _ = openStore(t, path, "edge")

	for _, seconds := range []int{10, 20, 40, 80, 160, 300, 300} {
		due := now.Add(time.Duration(seconds) * time.Second)
		require.NoError(t, store.Maintain(ctx, due.Add(-time.Millisecond)))
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
		require.NoError(t, store.Finish(ctx, *job, false, now))
	}
	now = now.Add(5 * time.Minute)
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
	require.NoError(t, store.Finish(ctx, *job, true, now))

	// The other pending release gets a fresh first retry after the destination recovers.
	job, err = store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, false, now))
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
		_, err := processor.Process(ctx, failed("one"), now)
		require.NoError(t, err)
		rollback := errors.New("rollback")
		err = store.Transact(ctx, func(tx ingestion.Transaction) error {
			_, err := tx.Block(ctx, "203.0.113.2", 2, now.Add(time.Hour), now)
			require.NoError(t, err)
			return rollback
		})
		require.ErrorIs(t, err, rollback)
		select {
		case <-store.Changes():
			t.Fatal("unexpected wake before decision commit")
		default:
		}
		_, err = processor.Process(ctx, failed("two"), now)
		require.NoError(t, err)
		select {
		case <-store.Changes():
		default:
			t.Fatal("missing wake after decision commit")
		}
	})

	t.Run("restart schedules the earlier of source expiry and destination retry", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "state.db")
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, _ := openStore(t, path, "receiver")
		_, err := store.BanManual(ctx, "203.0.113.1", now.Add(8*time.Second), "test", now)
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, false, now))
		require.NoError(t, store.Close())
		store, _ = openStore(t, path, "receiver")
		defer store.Close() //nolint:errcheck
		due, err := store.NextDeadline(ctx)
		require.NoError(t, err)
		require.True(t, now.Add(8*time.Second).Equal(due))
		require.NoError(t, store.Maintain(ctx, due))
		due, err = store.NextDeadline(ctx)
		require.NoError(t, err)
		require.True(t, now.Add(10*time.Second).Equal(due))
		job, err = store.Next(ctx, due)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
		require.NoError(t, store.Finish(ctx, *job, true, due))
		due, err = store.NextDeadline(ctx)
		require.NoError(t, err)
		assert.True(t, due.IsZero())
	})
}

func TestOptimize(t *testing.T) {
	t.Parallel()
	store, _ := openStore(t, filepath.Join(t.TempDir(), "optimize.db"))
	require.NoError(t, store.Optimize(t.Context()))
	require.NoError(t, store.Close())
	require.Error(t, store.Optimize(t.Context()), "optimization should not succeed on a closed store")
}
