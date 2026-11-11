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
	s := &manualStore{started: make(chan struct{}, 2), release: make(chan struct{})}
	close(s.release)
	r := &Runner{store: s, schedule: Schedule{PruneInterval: time.Hour, OptimizeInterval: time.Hour}}
	require.NoError(t, r.Trigger(t.Context(), OperationOptimize))
	status := r.Snapshot()
	require.NotNil(t, status.Optimize.LastSuccessAt)
	assert.Empty(t, status.Optimize.LastError)
	assert.Equal(t, time.Hour.String(), status.PruneInterval)
	assert.ErrorIs(t, r.Trigger(t.Context(), "vacuum"), ErrInvalidOperation)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	assert.ErrorIs(t, r.Trigger(ctx, OperationPrune), context.Canceled)
}

func TestManualMaintenanceFailure(t *testing.T) {
	t.Parallel()
	s := &manualStore{started: make(chan struct{}, 2), release: make(chan struct{}), failure: errors.New("disk unavailable")}
	close(s.release)
	r := &Runner{store: s, schedule: Schedule{PruneInterval: time.Hour, OptimizeInterval: time.Hour}}
	// A failed manual operation records the failed attempt.
	require.ErrorContains(t, r.Trigger(t.Context(), OperationPrune), "disk unavailable")
	assert.Contains(t, r.Snapshot().Prune.LastError, "disk unavailable")
}

func TestManualMaintenanceBusy(t *testing.T) {
	t.Parallel()
	s := &manualStore{started: make(chan struct{}, 2), release: make(chan struct{})}
	r := Start(t.Context(), s, Schedule{PruneInterval: time.Hour, OptimizeInterval: time.Hour}, discardLogger())
	defer func() { close(s.release); r.Close() }()
	select {
	case <-s.started:
	case <-time.After(3 * time.Second):
		t.Fatal("scheduled prune did not start")
	}
	assert.True(t, r.Snapshot().Prune.Running)
	assert.ErrorIs(t, r.Trigger(t.Context(), OperationOptimize), ErrBusy)
}
