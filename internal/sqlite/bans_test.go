package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestStoreApplyManualBan(t *testing.T) {
	t.Parallel()

	t.Run("persists manual ban across restart and expires it", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, _ := openStore(t, path, "edge")
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)

		created, err := service.BanManual(
			ctx,
			bans.ManualBanRequest{
				IP:       "::ffff:203.0.113.7",
				Duration: time.Minute,
				Reason:   "operator investigation",
			},
			now,
		)

		require.NoError(t, err)
		assert.Equal(t, "203.0.113.7", created.Decision.IP)
		assert.Equal(t, decisions.StateBanned, created.Decision.State)
		require.Len(t, created.Sources, 1)
		assert.Equal(t, bans.SourceManual, created.Sources[0].Kind)
		require.NoError(t, store.Close())

		store, _ = openStore(t, path, "edge")
		defer store.Close() //nolint:errcheck
		service, err = bans.NewAdminService(store)

		require.NoError(t, err)
		views, err := service.ListActive(ctx, now)

		require.NoError(t, err)
		require.Len(t, views, 1)
		assert.Equal(t, created.Decision.ID, views[0].Decision.ID)

		// An extension must not inadvertently shorten an active manual ban.
		updated, err := service.BanManual(ctx, bans.ManualBanRequest{
			IP:       "203.0.113.7",
			Duration: 10 * time.Second,
			Reason:   "still investigating",
		}, now)

		require.NoError(t, err)
		assert.Equal(t, created.Decision.ExpiresAt, updated.Decision.ExpiresAt)
		assert.Equal(t, "still investigating", updated.Sources[0].Reason)

		require.NoError(t, store.Maintain(ctx, created.Decision.ExpiresAt))
		views, err = service.ListActive(ctx, created.Decision.ExpiresAt)

		require.NoError(t, err)
		assert.Empty(t, views)
		view, err := service.GetDecision(ctx, created.Decision.ID, created.Decision.ExpiresAt)

		require.NoError(t, err)
		assert.Equal(t, decisions.StateUnbanned, view.Decision.State)
		assert.Empty(t, view.Sources)
		_, err = service.GetDecision(ctx, "does-not-exist", now)

		require.ErrorIs(t, err, bans.ErrNotFound)
	})

	t.Run("longer manual ban outlives automatic expiry", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(ctx, failed("first"), now)

		require.NoError(t, err)
		auto, err := ingestion.Process(ctx, failed("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)
		manual, err := service.BanManual(ctx, bans.ManualBanRequest{
			IP:       auto.IP,
			Duration: time.Hour,
			Reason:   "long ban",
		}, now)

		require.NoError(t, err)
		require.NoError(t, store.Maintain(ctx, auto.ExpiresAt))
		view, err := service.GetDecision(ctx, manual.Decision.ID, auto.ExpiresAt)

		require.NoError(t, err)
		assert.Equal(t, decisions.StateBanned, view.Decision.State)
		require.Len(t, view.Sources, 1)
		assert.Equal(t, bans.SourceManual, view.Sources[0].Kind)
		assert.Equal(t, manual.Decision.ExpiresAt, view.Decision.ExpiresAt)
	})
}

func TestStoreReleaseAllSources(t *testing.T) {
	t.Parallel()

	t.Run("removes manual and automatic sources and resets observation generation", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)

		_, err = ingestion.Process(ctx, failed("first"), now)

		require.NoError(t, err)
		auto, err := ingestion.Process(ctx, failed("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)

		manual, err := service.BanManual(ctx, bans.ManualBanRequest{
			IP:       auto.IP,
			Duration: time.Hour,
			Reason:   "Incident",
		}, now)

		require.NoError(t, err)
		assert.Equal(t, auto.ID, manual.Decision.ID)
		require.Len(t, manual.Sources, 2)
		assert.Equal(t, bans.SourceAutomatic, manual.Sources[0].Kind)
		assert.Equal(t, bans.SourceManual, manual.Sources[1].Kind)

		unbanned, err := service.Release(ctx, manual.Decision.ID, now.Add(time.Second))

		require.NoError(t, err)
		assert.Equal(t, decisions.StateUnbanned, unbanned.Decision.State)
		assert.Empty(t, unbanned.Sources)
		assert.Equal(t, manual.Decision.Revision+1, unbanned.Decision.Revision)

		job, err := store.Next(ctx, now.Add(time.Second))

		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, decisions.StateUnbanned, job.Decision.State, "the release must be queued")
		assert.Equal(t, unbanned.Decision.Revision, job.Decision.Revision)

		views, err := service.ListActive(ctx, now.Add(time.Second))

		require.NoError(t, err)
		assert.Empty(t, views)

		_, err = service.Release(ctx, manual.Decision.ID, now.Add(2*time.Second))

		require.ErrorIs(t, err, bans.ErrNotFound)

		// Replayed IDs remain deduplicated, but new login failures start at zero.
		decision, err := ingestion.Process(ctx, failed("first"), now.Add(3*time.Second))

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = ingestion.Process(ctx, failed("third"), now.Add(3*time.Second))

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = ingestion.Process(ctx, failed("fourth"), now.Add(4*time.Second))

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, unbanned.Decision.ID, decision.ID)
		assert.Equal(t, unbanned.Decision.Revision+1, decision.Revision)
	})

	t.Run("removes a purely automatic ban", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(ctx, failed("first"), now)

		require.NoError(t, err)
		auto, err := ingestion.Process(ctx, failed("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)

		result, err := service.Release(ctx, auto.ID, now.Add(time.Second))

		require.NoError(t, err)
		assert.Equal(t, decisions.StateUnbanned, result.Decision.State)
		assert.Empty(t, result.Sources)

		job, err := store.Next(ctx, now.Add(time.Second))

		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
	})

	t.Run("removes a purely manual ban", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "203.0.113.10",
			Duration: time.Hour,
			Reason:   "Incident",
		}, now)

		require.NoError(t, err)

		result, err := service.Release(t.Context(), created.Decision.ID, now.Add(time.Second))

		require.NoError(t, err)
		assert.Equal(t, decisions.StateUnbanned, result.Decision.State)
		assert.Empty(t, result.Sources)
	})
}

func TestStoreListActive(t *testing.T) {
	t.Parallel()

	t.Run("identifies both automatic and manual ban sources", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"))
		defer store.Close() //nolint:errcheck
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(t.Context(), failed("first"), now)

		require.NoError(t, err)
		_, err = ingestion.Process(t.Context(), failed("second"), now)

		require.NoError(t, err)
		_, err = service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "203.0.113.1",
			Duration: time.Hour,
			Reason:   "manual review",
		}, now)

		require.NoError(t, err)
		views, err := service.ListActive(t.Context(), now)

		require.NoError(t, err)
		require.Len(t, views, 1)
		require.Len(t, views[0].Sources, 2)
		assert.Equal(t, bans.SourceAutomatic, views[0].Sources[0].Kind)
		assert.Equal(t, bans.SourceManual, views[0].Sources[1].Kind)
		assert.Equal(t, "manual review", views[0].Sources[1].Reason)
	})
}

func TestRetiredDestination(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "warden.db")
	ctx := t.Context()
	store, _ := openStore(t, path, "old")
	service, err := bans.NewAdminService(store)

	require.NoError(t, err)
	now := time.Now()
	request := bans.ManualBanRequest{
		IP:       "203.0.113.40",
		Duration: time.Hour,
		Reason:   "incident",
	}
	view, err := service.BanManual(ctx, request, now)

	require.NoError(t, err)
	_, err = service.Release(ctx, view.Decision.ID, now)

	require.NoError(t, err)
	job, err := store.Next(ctx, now)

	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, true, now))
	require.NoError(t, store.Close())

	store, _ = openStore(t, path, "new")
	defer store.Close() //nolint:errcheck
	service, err = bans.NewAdminService(store)

	require.NoError(t, err)
	view, err = service.BanManual(ctx, request, now)

	require.NoError(t, err)
	require.Len(t, view.Deliveries, 1)
	assert.Equal(t, "new", view.Deliveries[0].Destination)
	job, err = store.Next(ctx, now)

	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "new", job.Destination)
}

// TestIdempotentManualBan verifies that unchanged desired state does not schedule a new delivery.
func TestIdempotentManualBan(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
	defer store.Close() //nolint:errcheck
	service, err := bans.NewAdminService(store)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Millisecond)
	request := bans.ManualBanRequest{
		IP:       "203.0.113.8",
		Duration: time.Hour,
		Reason:   "incident",
	}
	first, err := service.BanManual(t.Context(), request, now)
	require.NoError(t, err)

	job, err := store.Next(t.Context(), now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(t.Context(), *job, true, now))

	// Neither identical requests nor a reason-only change affect delivered fields.
	again, err := service.BanManual(t.Context(), request, now)
	require.NoError(t, err)
	assert.Equal(t, first.Decision, again.Decision)

	request.Reason = "still investigating"
	changedReason, err := service.BanManual(t.Context(), request, now)
	require.NoError(t, err)
	assert.Equal(t, first.Decision, changedReason.Decision)
	require.Len(t, changedReason.Sources, 1)
	assert.Equal(t, request.Reason, changedReason.Sources[0].Reason)

	pending, err := store.Next(t.Context(), now)
	require.NoError(t, err)
	assert.Nil(t, pending)

	// A real expiry extension must create a revision and a new delivery.
	request.Duration = 2 * time.Hour
	extended, err := service.BanManual(t.Context(), request, now)
	require.NoError(t, err)
	assert.Equal(t, first.Decision.Revision+1, extended.Decision.Revision)
	pending, err = store.Next(t.Context(), now)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, extended.Decision.Revision, pending.Decision.Revision)
}

// TestExpiringShorterSourceIsNoOp verifies a surviving source keeps the same desired revision.
func TestExpiringShorterSourceIsNoOp(t *testing.T) {
	t.Parallel()

	store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
	defer store.Close() //nolint:errcheck
	service, err := bans.NewAdminService(store)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err = ingestion.Process(t.Context(), failed("first"), now)
	require.NoError(t, err)
	_, err = ingestion.Process(t.Context(), failed("second"), now)
	require.NoError(t, err)

	manual, err := service.BanManual(t.Context(), bans.ManualBanRequest{
		IP:       "203.0.113.1",
		Duration: time.Hour,
		Reason:   "extended review",
	}, now)
	require.NoError(t, err)
	assert.Len(t, manual.Sources, 2)

	// Automatic expiry removes a source but does not change the effective block.
	require.NoError(t, store.Maintain(t.Context(), now.Add(16*time.Minute)))
	remaining, err := service.GetDecision(t.Context(), manual.Decision.ID, now.Add(16*time.Minute))
	require.NoError(t, err)
	assert.Len(t, remaining.Sources, 1)
	assert.Equal(t, manual.Decision, remaining.Decision)

	// The final expiry creates one release and repeated maintenance is a no-op.
	require.NoError(t, store.Maintain(t.Context(), now.Add(time.Hour)))
	released, err := service.GetDecision(t.Context(), manual.Decision.ID, now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, decisions.StateUnbanned, released.Decision.State)
	assert.Equal(t, manual.Decision.Revision+1, released.Decision.Revision)
	require.NoError(t, store.Maintain(t.Context(), now.Add(time.Hour)))
	again, err := service.GetDecision(t.Context(), manual.Decision.ID, now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, released.Decision, again.Decision)
}
