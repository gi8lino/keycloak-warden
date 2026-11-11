package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinishIgnoresStaleDeliveryFailure ensures old delivery failures cannot delay new revisions.
func TestFinishIgnoresStaleDeliveryFailure(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "test.db"), "edge")
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := store.ApplyManualBan(ctx, "203.0.113.1", now.Add(time.Hour), "investigation", now)
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, first.Decision.Revision, job.Decision.Revision)

	// The desired state changes while the old revision is in flight.
	second, err := store.ApplyManualBan(ctx, "203.0.113.1", now.Add(2*time.Hour), "extended", now)
	require.NoError(t, err)
	require.Greater(t, second.Decision.Revision, first.Decision.Revision)

	// A failed attempt against revision 1 must not postpone revision 2.
	require.NoError(t, store.Finish(ctx, *job, false, now))
	pending, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, second.Decision, pending.Decision)
}
