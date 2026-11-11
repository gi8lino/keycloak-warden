package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

func TestBulkBanListing(t *testing.T) {
	t.Parallel()

	t.Run("preserves order, independent sources, acknowledgements and nonnil empty slices", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, processor := openStore(t, path, "zeta", "alpha")
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)

		// Insert out of IP order so the listing order must be enforced by SQL.
		third, err := store.ApplyManualBan(ctx, "203.0.113.30", now.Add(time.Hour), "third", now)
		require.NoError(t, err)
		first, err := store.ApplyManualBan(ctx, "203.0.113.10", now.Add(time.Hour), "first", now)
		require.NoError(t, err)

		event := failed("bulk-first")
		event.IP = "203.0.113.20"
		_, err = processor.Process(ctx, event, now)
		require.NoError(t, err)
		event.ID = "bulk-second"
		_, err = processor.Process(ctx, event, now)
		require.NoError(t, err)
		second, err := store.ApplyManualBan(ctx, "203.0.113.20", now.Add(time.Hour), "second", now)
		require.NoError(t, err)

		views, err := store.ListActive(ctx, now)
		require.NoError(t, err)
		require.Len(t, views, 3)
		assert.Equal(t, first.Decision.ID, views[0].Decision.ID)
		assert.Equal(t, second.Decision.ID, views[1].Decision.ID)
		assert.Equal(t, third.Decision.ID, views[2].Decision.ID)
		require.Len(t, views[1].Sources, 2)
		assert.Equal(t, bans.SourceAutomatic, views[1].Sources[0].Kind)
		assert.Equal(t, bans.SourceManual, views[1].Sources[1].Kind)
		assert.Equal(t, "second", views[1].Sources[1].Reason)
		for _, view := range views {
			require.Len(t, view.Deliveries, 2)
			assert.Equal(t, "alpha", view.Deliveries[0].Destination)
			assert.Equal(t, "zeta", view.Deliveries[1].Destination)
			assert.NotNil(t, view.Sources)
			assert.NotNil(t, view.Deliveries)
		}

		// A release must not appear in the bulk list or leak its deliveries.
		_, err = store.ReleaseAllSources(ctx, second.Decision.ID, now.Add(time.Second))
		require.NoError(t, err)
		remaining, err := store.ListActive(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.Len(t, remaining, 2)
		assert.Equal(t, first.Decision.ID, remaining[0].Decision.ID)
		assert.Equal(t, third.Decision.ID, remaining[1].Decision.ID)

		// No active decisions should serialize as an empty array, not null.
		expired, err := store.ListActive(ctx, now.Add(2*time.Hour))
		require.NoError(t, err)
		assert.NotNil(t, expired)
		assert.Empty(t, expired)
	})
}
