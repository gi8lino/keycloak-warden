package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestInspect(t *testing.T) {
	t.Parallel()

	t.Run("inspects a single decision", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, ingestion := openStore(t, path, "edge")
		defer store.Close() // nolint:errcheck

		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := ingestion.Process(t.Context(), failed("one"), now)
		require.NoError(t, err)
		decision, err := ingestion.Process(t.Context(), failed("two"), now)
		require.NoError(t, err)
		require.NotNil(t, decision)

		records, err := sqlite.InspectMany(t.Context(), path, []string{decision.ID})
		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Equal(t, *decision, records[0].Decision)
		assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 0}}, records[0].Deliveries)
		require.Len(t, records[0].Sources, 1)
		assert.Equal(t, bans.SourceAutomatic, records[0].Sources[0].Kind)
	})
}

func TestInspectMany(t *testing.T) {
	t.Parallel()

	t.Run("reads decisions in requested order with independent deliveries", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, ingestion := openStore(t, path, "edge")
		defer store.Close() // nolint:errcheck

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)

		_, err := ingestion.Process(ctx, failed("first-one"), now)
		require.NoError(t, err)
		first, err := ingestion.Process(ctx, failed("first-two"), now)
		require.NoError(t, err)
		require.NotNil(t, first)

		secondEvent := failed("second-one")
		secondEvent.IP = "203.0.113.2"
		_, err = ingestion.Process(ctx, secondEvent, now.Add(time.Second))
		require.NoError(t, err)
		secondEvent.ID = "second-two"
		second, err := ingestion.Process(ctx, secondEvent, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, second)

		require.NoError(t, store.Finish(ctx, actions.Job{Decision: *first, Destination: "edge"}, true, now))

		records, err := sqlite.InspectMany(ctx, path, []string{second.ID, first.ID})
		require.NoError(t, err)
		require.Len(t, records, 2)
		assert.Equal(t, *second, records[0].Decision)
		assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 0}}, records[0].Deliveries)
		assert.Equal(t, *first, records[1].Decision)
		assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 1}}, records[1].Deliveries)

		// The online ban readers must return the same decision and delivery data.
		firstBan, err := store.GetDecision(ctx, first.ID, now)
		require.NoError(t, err)
		assert.Equal(t, records[1].Decision, firstBan.Decision)
		assert.Equal(t, records[1].Deliveries, firstBan.Deliveries)
		assert.Equal(t, records[1].Sources, firstBan.Sources)
		secondBan, err := store.GetDecision(ctx, second.ID, now.Add(time.Second))
		require.NoError(t, err)
		assert.Equal(t, records[0].Decision, secondBan.Decision)
		assert.Equal(t, records[0].Deliveries, secondBan.Deliveries)
		assert.Equal(t, records[0].Sources, secondBan.Sources)
	})

	t.Run("missing decision reports its ID without partial results", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, ingestion := openStore(t, path)
		defer store.Close() // nolint:errcheck

		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := ingestion.Process(t.Context(), failed("one"), now)
		require.NoError(t, err)
		decision, err := ingestion.Process(t.Context(), failed("two"), now)
		require.NoError(t, err)
		require.NotNil(t, decision)

		records, err := sqlite.InspectMany(t.Context(), path, []string{decision.ID, "missing-id"})
		require.ErrorIs(t, err, bans.ErrNotFound)
		require.ErrorContains(t, err, "missing-id")
		assert.Nil(t, records)
	})
}

func TestInspectReleasedDecision(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "warden.db")
	store, _ := openStore(t, path, "edge")
	defer store.Close() //nolint:errcheck

	service, err := bans.NewAdminService(store)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Millisecond)
	created, err := service.BanManual(t.Context(), bans.ManualBanRequest{
		IP:       "203.0.113.25",
		Duration: time.Hour,
		Reason:   "incident",
	}, now)
	require.NoError(t, err)
	released, err := service.Release(t.Context(), created.Decision.ID, now.Add(time.Second))
	require.NoError(t, err)
	records, err := sqlite.InspectMany(t.Context(), path, []string{created.Decision.ID})
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Equal(t, released.Decision, records[0].Decision)
	assert.Empty(t, records[0].Sources)
	assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 0}}, records[0].Deliveries)
}

func TestListActiveBans(t *testing.T) {
	t.Parallel()

	t.Run("read-only listing preserves both source types", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, ingestion := openStore(t, path)
		defer store.Close() // nolint:errcheck

		service, err := bans.NewAdminService(store)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(t.Context(), failed("one"), now)
		require.NoError(t, err)
		_, err = ingestion.Process(t.Context(), failed("two"), now)
		require.NoError(t, err)
		_, err = service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "203.0.113.1",
			Duration: time.Hour,
			Reason:   "support",
		}, now)
		require.NoError(t, err)

		records, err := sqlite.ListActiveBans(t.Context(), path, now)
		require.NoError(t, err)
		require.Len(t, records, 1)
		require.Len(t, records[0].Sources, 2)
		assert.Equal(t, bans.SourceAutomatic, records[0].Sources[0].Kind)
		assert.Equal(t, bans.SourceManual, records[0].Sources[1].Kind)
		assert.Equal(t, "support", records[0].Sources[1].Reason)
	})
}
