package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

func TestStoreBanManual(t *testing.T) {
	t.Parallel()

	t.Run("persists manual ban across restart and expires it", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, _ := openStore(t, path, "edge")
		service, err := bans.New(store)

		require.NoError(t, err)

		created, err := service.Ban(
			ctx,
			bans.Request{IP: "::ffff:203.0.113.7", Duration: time.Minute, Reason: "operator investigation"},
			now,
		)

		require.NoError(t, err)
		assert.Equal(t, "203.0.113.7", created.Decision.IP)
		assert.True(t, created.Decision.Active)
		require.Len(t, created.Sources, 1)
		assert.Equal(t, bans.SourceManual, created.Sources[0].Kind)
		require.NoError(t, store.Close())

		store, _ = openStore(t, path, "edge")
		defer store.Close() //nolint:errcheck
		service, err = bans.New(store)

		require.NoError(t, err)
		views, err := service.List(ctx, now)

		require.NoError(t, err)
		require.Len(t, views, 1)
		assert.Equal(t, created.Decision.ID, views[0].Decision.ID)

		// An extension must not inadvertently shorten an active manual ban.
		updated, err := service.Ban(ctx, bans.Request{IP: "203.0.113.7", Duration: 10 * time.Second, Reason: "still investigating"}, now)

		require.NoError(t, err)
		assert.Equal(t, created.Decision.ExpiresAt, updated.Decision.ExpiresAt)
		assert.Equal(t, "still investigating", updated.Sources[0].Reason)

		require.NoError(t, store.Maintain(ctx, created.Decision.ExpiresAt))
		views, err = service.List(ctx, created.Decision.ExpiresAt)

		require.NoError(t, err)
		assert.Empty(t, views)
		view, err := service.Get(ctx, created.Decision.ID, created.Decision.ExpiresAt)

		require.NoError(t, err)
		assert.False(t, view.Decision.Active)
		assert.Empty(t, view.Sources)
		_, err = service.Get(ctx, "does-not-exist", now)

		require.ErrorIs(t, err, bans.ErrNotFound)
	})

	t.Run("longer manual ban outlives automatic expiry", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.New(store)

		require.NoError(t, err)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(ctx, failed("first"), now)

		require.NoError(t, err)
		auto, err := ingestion.Process(ctx, failed("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)
		manual, err := service.Ban(ctx, bans.Request{IP: auto.IP, Duration: time.Hour, Reason: "long ban"}, now)

		require.NoError(t, err)
		require.NoError(t, store.Maintain(ctx, auto.ExpiresAt))
		view, err := service.Get(ctx, manual.Decision.ID, auto.ExpiresAt)

		require.NoError(t, err)
		assert.True(t, view.Decision.Active)
		require.Len(t, view.Sources, 1)
		assert.Equal(t, bans.SourceManual, view.Sources[0].Kind)
		assert.Equal(t, manual.Decision.ExpiresAt, view.Decision.ExpiresAt)
	})
}

func TestStoreUnbanAll(t *testing.T) {
	t.Parallel()

	t.Run("removes manual and automatic sources and clears failure count", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.New(store)

		require.NoError(t, err)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)

		_, err = ingestion.Process(ctx, failed("first"), now)

		require.NoError(t, err)
		auto, err := ingestion.Process(ctx, failed("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)

		manual, err := service.Ban(ctx, bans.Request{IP: auto.IP, Duration: time.Hour, Reason: "Incident"}, now)

		require.NoError(t, err)
		assert.Equal(t, auto.ID, manual.Decision.ID)
		require.Len(t, manual.Sources, 2)
		assert.Equal(t, bans.SourceAutomatic, manual.Sources[0].Kind)
		assert.Equal(t, bans.SourceManual, manual.Sources[1].Kind)

		unbanned, err := service.Unban(ctx, manual.Decision.ID, now.Add(time.Second))

		require.NoError(t, err)
		assert.False(t, unbanned.Decision.Active)
		assert.Zero(t, unbanned.Decision.Failures)
		assert.Empty(t, unbanned.Sources)
		assert.Equal(t, manual.Decision.Revision+1, unbanned.Decision.Revision)

		job, err := store.Next(ctx, now.Add(time.Second))

		require.NoError(t, err)
		require.NotNil(t, job)
		assert.False(t, job.Decision.Active, "the release must be queued")
		assert.Equal(t, unbanned.Decision.Revision, job.Decision.Revision)

		views, err := service.List(ctx, now.Add(time.Second))

		require.NoError(t, err)
		assert.Empty(t, views)

		_, err = service.Unban(ctx, manual.Decision.ID, now.Add(2*time.Second))

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
		assert.Equal(t, 2, decision.Failures)
		assert.Equal(t, unbanned.Decision.ID, decision.ID)
		assert.Equal(t, unbanned.Decision.Revision+1, decision.Revision)
	})

	t.Run("removes a purely automatic ban", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.New(store)

		require.NoError(t, err)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(ctx, failed("first"), now)

		require.NoError(t, err)
		auto, err := ingestion.Process(ctx, failed("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)

		result, err := service.Unban(ctx, auto.ID, now.Add(time.Second))

		require.NoError(t, err)
		assert.False(t, result.Decision.Active)
		assert.Zero(t, result.Decision.Failures)
		assert.Empty(t, result.Sources)

		job, err := store.Next(ctx, now.Add(time.Second))

		require.NoError(t, err)
		require.NotNil(t, job)
		assert.False(t, job.Decision.Active)
	})

	t.Run("removes a purely manual ban", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "warden.db"), "edge")
		defer store.Close() //nolint:errcheck
		service, err := bans.New(store)

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := service.Ban(t.Context(), bans.Request{IP: "203.0.113.10", Duration: time.Hour, Reason: "Incident"}, now)

		require.NoError(t, err)

		result, err := service.Unban(t.Context(), created.Decision.ID, now.Add(time.Second))

		require.NoError(t, err)
		assert.False(t, result.Decision.Active)
		assert.Empty(t, result.Sources)
	})
}

func TestStoreListBans(t *testing.T) {
	t.Parallel()

	t.Run("identifies both automatic and manual ban sources", func(t *testing.T) {
		t.Parallel()

		store, ingestion := openStore(t, filepath.Join(t.TempDir(), "warden.db"))
		defer store.Close() //nolint:errcheck
		service, err := bans.New(store)

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(t.Context(), failed("first"), now)

		require.NoError(t, err)
		_, err = ingestion.Process(t.Context(), failed("second"), now)

		require.NoError(t, err)
		_, err = service.Ban(t.Context(), bans.Request{IP: "203.0.113.1", Duration: time.Hour, Reason: "manual review"}, now)

		require.NoError(t, err)
		views, err := service.List(t.Context(), now)

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
	service, err := bans.New(store)

	require.NoError(t, err)
	now := time.Now()
	request := bans.Request{IP: "203.0.113.40", Duration: time.Hour, Reason: "incident"}
	view, err := service.Ban(ctx, request, now)

	require.NoError(t, err)
	_, err = service.Unban(ctx, view.Decision.ID, now)

	require.NoError(t, err)
	job, err := store.Next(ctx, now)

	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, true, now))
	require.NoError(t, store.Close())

	store, _ = openStore(t, path, "new")
	defer store.Close() //nolint:errcheck
	service, err = bans.New(store)

	require.NoError(t, err)
	view, err = service.Ban(ctx, request, now)

	require.NoError(t, err)
	require.Len(t, view.Deliveries, 1)
	assert.Equal(t, "new", view.Deliveries[0].Destination)
	job, err = store.Next(ctx, now)

	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "new", job.Destination)
}
