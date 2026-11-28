package maintenance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore records each maintenance attempt and optionally fails the first one.
type fakeStore struct {
	// pruneCalls counts observation cleanup attempts.
	pruneCalls atomic.Int32
	// lastCutoffMillis records the cutoff supplied by maintenance.
	lastCutoffMillis atomic.Int64
	// lastIncidentCutoffMillis records the incident cutoff supplied by maintenance.
	lastIncidentCutoffMillis atomic.Int64
	// optimizeCalls counts planner optimization attempts.
	optimizeCalls atomic.Int32
	// pruneFailure causes the first cleanup attempt to fail.
	pruneFailure bool
	// optimizeFailure causes the first optimization attempt to fail.
	optimizeFailure bool
}

// Prune records a cleanup attempt and optionally injects a transient failure.
func (s *fakeStore) Prune(_ context.Context, cutoff, incidentCutoff time.Time) error {
	s.lastCutoffMillis.Store(cutoff.UnixMilli())
	s.lastIncidentCutoffMillis.Store(incidentCutoff.UnixMilli())
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

func TestValidateIncidentRetention(t *testing.T) {
	t.Parallel()

	t.Run("accepts minimum", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateIncidentRetention(MinIncidentRetention))
	})

	t.Run("accepts default", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateIncidentRetention(DefaultIncidentRetention))
	})

	t.Run("accepts maximum", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateIncidentRetention(MaxIncidentRetention))
	})

	t.Run("rejects zero", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateIncidentRetention(0), "incident-retention")
	})

	t.Run("rejects below minimum", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateIncidentRetention(MinIncidentRetention-time.Second), "incident-retention")
	})

	t.Run("rejects above maximum", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateIncidentRetention(MaxIncidentRetention+time.Second), "incident-retention")
	})
}

func TestRecurringMaintenance(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		store := &fakeStore{}
		runner := Start(t.Context(), store, Schedule{PruneInterval: time.Minute, OptimizeInterval: 2 * time.Minute}, Retention{Observations: 24 * time.Hour, Incidents: 30 * 24 * time.Hour}, discardLogger())
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
		runner := Start(t.Context(), store, sched, Retention{Observations: 24 * time.Hour, Incidents: 30 * 24 * time.Hour}, discardLogger())
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
		runner := Start(t.Context(), store, sched, Retention{Observations: 24 * time.Hour, Incidents: 30 * 24 * time.Hour}, discardLogger())
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
			logger:    discardLogger(),
			store:     store,
			retention: Retention{Observations: 48 * time.Hour, Incidents: 30 * time.Hour},
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
		incidentCutoff := time.UnixMilli(store.lastIncidentCutoffMillis.Load())
		assert.WithinDuration(t, now.Add(-30*time.Hour), incidentCutoff, time.Second)
	})
}

// manualStore is a blocking maintenance store used to verify serialized requests.
type manualStore struct {
	// started signals that a cleanup operation entered SQLite.
	started chan struct{}
	// release allows a blocked cleanup to complete.
	release chan struct{}
	// failure is returned from cleanup when configured.
	failure error
}

// Prune blocks until released, allowing a concurrent maintenance request.
func (s *manualStore) Prune(ctx context.Context, _, _ time.Time) error {
	select {
	case s.started <- struct{}{}:
	default:
	}

	select {
	case <-s.release:
		return s.failure
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Optimize completes without touching cleanup state.
func (*manualStore) Optimize(context.Context) error { return nil }

func TestManualMaintenance(t *testing.T) {
	t.Parallel()

	t.Run("records a successful optimization", func(t *testing.T) {
		t.Parallel()

		store := &manualStore{}
		runner := &Runner{
			logger: discardLogger(),
			store:  store,
			schedule: Schedule{
				PruneInterval:    time.Hour,
				OptimizeInterval: time.Hour,
			},
		}

		require.NoError(t, runner.Trigger(t.Context(), OperationOptimize))

		status := runner.Snapshot()
		require.NotNil(t, status.Optimize.LastSuccessAt)
		assert.Empty(t, status.Optimize.LastError)
		assert.Equal(t, time.Hour.String(), status.PruneInterval)
	})

	t.Run("rejects unsupported operations", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{logger: discardLogger()}

		require.ErrorIs(t, runner.Trigger(t.Context(), "vacuum"), ErrInvalidOperation)
	})

	t.Run("propagates canceled context", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		runner := &Runner{logger: discardLogger()}

		require.ErrorIs(t, runner.Trigger(ctx, OperationPrune), context.Canceled)
	})

	t.Run("records a failed prune", func(t *testing.T) {
		t.Parallel()

		store := &manualStore{
			release: make(chan struct{}),
			failure: errors.New("disk unavailable"),
		}
		close(store.release)

		runner := &Runner{
			logger: discardLogger(),
			store:  store,
			schedule: Schedule{
				PruneInterval:    time.Hour,
				OptimizeInterval: time.Hour,
			},
		}

		require.ErrorContains(t, runner.Trigger(t.Context(), OperationPrune), "disk unavailable")
		assert.Contains(t, runner.Snapshot().Prune.LastError, "disk unavailable")
	})

	t.Run("reports busy during scheduled pruning", func(t *testing.T) {
		t.Parallel()

		store := &manualStore{
			started: make(chan struct{}, 2),
			release: make(chan struct{}),
		}
		runner := Start(t.Context(), store, Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: time.Hour,
		}, Retention{Observations: 24 * time.Hour, Incidents: 30 * 24 * time.Hour}, discardLogger())
		defer func() {
			close(store.release)
			runner.Close()
		}()

		select {
		case <-store.started:
		case <-time.After(3 * time.Second):
			require.FailNow(t, "scheduled prune did not start")
		}

		assert.True(t, runner.Snapshot().Prune.Running)
		assert.ErrorIs(t, runner.Trigger(t.Context(), OperationOptimize), ErrBusy)
	})
}

func TestMaintenanceOutcomeLogs(t *testing.T) {
	t.Parallel()
	t.Run("manual completion includes trigger operation and duration", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		runner := &Runner{store: &fakeStore{}, logger: slog.New(slog.NewJSONHandler(&output, nil))}
		require.NoError(t, runner.Trigger(t.Context(), OperationOptimize))
		assert.Contains(t, output.String(), `"event":"database_maintenance_completed"`)
		assert.Contains(t, output.String(), `"trigger":"manual"`)
		assert.Contains(t, output.String(), `"operation":"optimize"`)
		assert.Contains(t, output.String(), `"duration_ms":`)
		assert.Contains(t, output.String(), `"level":"INFO"`)
	})
	t.Run("scheduled completion uses the same outcome record", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		runner := &Runner{store: &fakeStore{}, retention: Retention{Observations: time.Hour, Incidents: 30 * 24 * time.Hour}, logger: slog.New(slog.NewJSONHandler(&output, nil))}
		require.NoError(t, runner.execute(t.Context(), OperationPrune, "scheduled"))
		assert.Contains(t, output.String(), `"event":"database_maintenance_completed"`)
		assert.Contains(t, output.String(), `"trigger":"scheduled"`)
		assert.Contains(t, output.String(), `"operation":"prune"`)
	})
	t.Run("failure never reports completion", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		runner := &Runner{store: &fakeStore{optimizeFailure: true}, logger: slog.New(slog.NewJSONHandler(&output, nil))}
		require.Error(t, runner.Trigger(t.Context(), OperationOptimize))
		assert.Contains(t, output.String(), `"event":"database_maintenance_failed"`)
		assert.Contains(t, output.String(), `"outcome":"failed"`)
		assert.Contains(t, output.String(), `"level":"WARN"`)
		assert.NotContains(t, output.String(), "database_maintenance_completed")
	})
}

// TestSnapshotWorkerLifecycle verifies lifecycle and task state share one snapshot.
func TestSnapshotWorkerLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("reports idle with task schedules", func(t *testing.T) {
		t.Parallel()

		started := time.Now().UTC()
		runner := &Runner{
			startedAt: started,
			done:      make(chan struct{}),
			retention: Retention{
				Observations: MinObservationRetention,
				Incidents:    DefaultIncidentRetention,
			},
			schedule: Schedule{
				PruneInterval:    time.Hour,
				OptimizeInterval: 24 * time.Hour,
			},
		}

		status := runner.Snapshot()

		assert.Equal(t, model.WorkerIdle, status.State)
		assert.Equal(t, started, status.StartedAt)
		assert.Equal(t, "1h0m0s", status.PruneInterval)
		assert.Equal(t, "24h0m0s", status.OptimizeInterval)
		assert.Equal(t, "24h0m0s", status.ObservationRetention)
		assert.Equal(t, "720h0m0s", status.IncidentRetention)
		assert.False(t, status.Prune.Running)
	})

	t.Run("reports processing and current task state together", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.pruneStatus.Running = true

		status := runner.Snapshot()

		assert.Equal(t, model.WorkerProcessing, status.State)
		assert.True(t, status.Prune.Running)
		assert.False(t, status.Optimize.Running)
	})

	t.Run("reports optimization as processing", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		runner.optimizeStatus.Running = true

		status := runner.Snapshot()

		assert.Equal(t, model.WorkerProcessing, status.State)
		assert.True(t, status.Optimize.Running)
	})

	t.Run("reports stopped after completion", func(t *testing.T) {
		t.Parallel()

		runner := &Runner{done: make(chan struct{})}
		close(runner.done)

		status := runner.Snapshot()

		assert.Equal(t, model.WorkerStopped, status.State)
	})
}
