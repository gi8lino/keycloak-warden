package maintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
func (s *manualStore) Prune(ctx context.Context, _ time.Time) error {
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
			store: store,
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

		runner := &Runner{}

		require.ErrorIs(t, runner.Trigger(t.Context(), "vacuum"), ErrInvalidOperation)
	})

	t.Run("propagates canceled context", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		runner := &Runner{}

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
			store: store,
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
		}, discardLogger())
		defer func() {
			close(store.release)
			runner.Close()
		}()

		select {
		case <-store.started:
		case <-time.After(3 * time.Second):
			t.Fatal("scheduled prune did not start")
		}

		assert.True(t, runner.Snapshot().Prune.Running)
		assert.ErrorIs(t, runner.Trigger(t.Context(), OperationOptimize), ErrBusy)
	})
}
