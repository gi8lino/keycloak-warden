package maintenance

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore records each maintenance attempt and optionally fails the first one.
type fakeStore struct {
	// pruneCalls counts observation cleanup attempts.
	pruneCalls atomic.Int32
	// lastCutoffMillis records the cutoff supplied by maintenance.
	lastCutoffMillis atomic.Int64
	// optimizeCalls counts planner optimization attempts.
	optimizeCalls atomic.Int32
	// pruneFailure causes the first cleanup attempt to fail.
	pruneFailure bool
	// optimizeFailure causes the first optimization attempt to fail.
	optimizeFailure bool
}

// Prune records a cleanup attempt and optionally injects a transient failure.
func (s *fakeStore) Prune(_ context.Context, cutoff time.Time) error {
	s.lastCutoffMillis.Store(cutoff.UnixMilli())
	attempt := s.pruneCalls.Add(1)
	if s.pruneFailure && attempt == 1 {
		return errors.New("prune failed")
	}
	return nil
}

// Optimize records an optimization attempt and optionally injects a transient failure.
func (s *fakeStore) Optimize(context.Context) error {
	attempt := s.optimizeCalls.Add(1)
	if s.optimizeFailure && attempt == 1 {
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
		assert.ErrorContains(t, err, MinInterval.String())
	})

	t.Run("rejects short optimize interval", func(t *testing.T) {
		t.Parallel()

		sched := Schedule{
			PruneInterval:    MinInterval,
			OptimizeInterval: time.Millisecond,
		}
		err := sched.Validate()
		require.ErrorContains(t, err, "optimize-interval")
		assert.ErrorContains(t, err, MaxInterval.String())
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
		runner := Start(t.Context(), store, Schedule{PruneInterval: time.Minute, OptimizeInterval: 2 * time.Minute}, 24*time.Hour, discardLogger())
		defer runner.Close()

		synctest.Wait()
		assert.Equal(t, int32(1), store.pruneCalls.Load(), "pruning runs immediately")
		assert.Zero(t, store.optimizeCalls.Load(), "opening SQLite already performs the initial optimization")

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, int32(2), store.pruneCalls.Load())
		assert.Zero(t, store.optimizeCalls.Load())

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, int32(3), store.pruneCalls.Load())
		assert.Equal(t, int32(1), store.optimizeCalls.Load())
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
		runner := Start(t.Context(), store, sched, 24*time.Hour, discardLogger())
		defer runner.Close()

		synctest.Wait()
		assert.Equal(t, int32(1), store.pruneCalls.Load())

		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(1), store.optimizeCalls.Load())

		time.Sleep(4 * time.Second)
		synctest.Wait()
		assert.Equal(t, int32(2), store.pruneCalls.Load(), "failed prune retried after five seconds")
		assert.Equal(t, int32(1), store.optimizeCalls.Load(), "failed optimization is retried independently")

		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(2), store.optimizeCalls.Load())
	})
}

func TestMaintenanceClose(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		store := &fakeStore{}
		sched := Schedule{PruneInterval: time.Hour, OptimizeInterval: time.Hour}
		runner := Start(t.Context(), store, sched, 24*time.Hour, discardLogger())
		synctest.Wait()
		runner.Close()
		runner.Close()
		assert.Equal(t, int32(1), store.pruneCalls.Load())
		assert.Zero(t, store.optimizeCalls.Load())
	})
}

func TestPruneRetention(t *testing.T) {
	t.Parallel()

	t.Run("calculates the cutoff from application retention", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		runner := &Runner{
			store:     store,
			retention: 48 * time.Hour,
			schedule: Schedule{
				PruneInterval:    time.Hour,
				OptimizeInterval: time.Hour,
			},
		}
		now := time.Now()

		err := runner.Trigger(t.Context(), OperationPrune)

		require.NoError(t, err)
		cutoff := time.UnixMilli(store.lastCutoffMillis.Load())
		assert.WithinDuration(t, now.Add(-48*time.Hour), cutoff, time.Second)
	})
}
