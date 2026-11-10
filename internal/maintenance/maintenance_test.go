package maintenance

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore records each maintenance attempt and optionally fails the first one.
type fakeStore struct {
	// pruneCalls counts observation cleanup attempts.
	pruneCalls int
	// optimizeCalls counts planner optimization attempts.
	optimizeCalls int
	// pruneFailure causes the first cleanup attempt to fail.
	pruneFailure bool
	// optimizeFailure causes the first optimization attempt to fail.
	optimizeFailure bool
}

// Prune records a cleanup attempt and optionally injects a transient failure.
func (s *fakeStore) Prune(context.Context, time.Time) error {
	s.pruneCalls++
	if s.pruneFailure && s.pruneCalls == 1 {
		return errors.New("prune failed")
	}
	return nil
}

// Optimize records an optimization attempt and optionally injects a transient failure.
func (s *fakeStore) Optimize(context.Context) error {
	s.optimizeCalls++
	if s.optimizeFailure && s.optimizeCalls == 1 {
		return errors.New("optimize failed")
	}
	return nil
}

// discardLogger produces a quiet logger for deterministic scheduling tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestScheduleValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts configured intervals", func(t *testing.T) {
		t.Parallel()
		sched := Schedule{
			PruneInterval:    MinInterval,
			OptimizeInterval: time.Hour,
		}
		err := sched.Validate()
		assert.NoError(t, err)
	})

	t.Run("rejects missing prune interval", func(t *testing.T) {
		t.Parallel()

		sched := Schedule{
			OptimizeInterval: time.Hour,
			PruneInterval:    0,
		}
		err := sched.Validate()
		require.ErrorContains(t, err, "prune-interval")
	})

	t.Run("rejects short optimize interval", func(t *testing.T) {
		t.Parallel()
		sched := Schedule{
			PruneInterval:    MinInterval,
			OptimizeInterval: time.Millisecond,
		}
		err := sched.Validate()
		require.ErrorContains(t, err, "optimize-interval")
	})

	t.Run("rejects overlong intervals", func(t *testing.T) {
		t.Parallel()
		sched := Schedule{
			PruneInterval:    MaxInterval + time.Second,
			OptimizeInterval: time.Hour,
		}
		err := sched.Validate()
		require.ErrorContains(t, err, "prune-interval")
	})
}

func TestRecurringMaintenance(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		store := &fakeStore{}
		runner := Start(t.Context(), store, Schedule{PruneInterval: time.Minute, OptimizeInterval: 2 * time.Minute}, discardLogger())
		defer runner.Close()

		synctest.Wait()
		assert.Equal(t, 1, store.pruneCalls, "pruning runs immediately")
		assert.Zero(t, store.optimizeCalls, "opening SQLite already performs the initial optimization")

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 2, store.pruneCalls)
		assert.Zero(t, store.optimizeCalls)

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 3, store.pruneCalls)
		assert.Equal(t, 1, store.optimizeCalls)
	})
}

func TestMaintenanceRetry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		store := &fakeStore{
			pruneFailure:    true,
			optimizeFailure: true,
		}
		sched := Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: time.Second,
		}
		runner := Start(t.Context(), store, sched, discardLogger())
		defer runner.Close()

		synctest.Wait()
		assert.Equal(t, 1, store.pruneCalls)

		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, 1, store.optimizeCalls)

		time.Sleep(4 * time.Second)
		synctest.Wait()
		assert.Equal(t, 2, store.pruneCalls, "failed prune retried after five seconds")
		assert.Equal(t, 1, store.optimizeCalls, "failed optimization is retried independently")

		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, 2, store.optimizeCalls)
	})
}

func TestMaintenanceClose(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		store := &fakeStore{}
		sched := Schedule{PruneInterval: time.Hour, OptimizeInterval: time.Hour}
		runner := Start(t.Context(), store, sched, discardLogger())
		synctest.Wait()
		runner.Close()
		runner.Close()
		assert.Equal(t, 1, store.pruneCalls)
		assert.Zero(t, store.optimizeCalls)
	})
}
