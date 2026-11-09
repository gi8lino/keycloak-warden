package sqlite_test

import (
	"database/sql"
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

	t.Run("single decision inspection remains supported", func(t *testing.T) {
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

		view, err := sqlite.Inspect(t.Context(), path, decision.ID)
		require.NoError(t, err)
		assert.Equal(t, *decision, view.Decision)
		assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 0}}, view.Deliveries)
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

		views, err := sqlite.InspectMany(ctx, path, []string{second.ID, first.ID})
		require.NoError(t, err)
		require.Len(t, views, 2)
		assert.Equal(t, *second, views[0].Decision)
		assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 0}}, views[0].Deliveries)
		assert.Equal(t, *first, views[1].Decision)
		assert.Equal(t, []decisions.Acknowledgement{{Destination: "edge", Revision: 1}}, views[1].Deliveries)
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

		views, err := sqlite.InspectMany(t.Context(), path, []string{decision.ID, "missing-id"})
		require.ErrorIs(t, err, sql.ErrNoRows)
		require.ErrorContains(t, err, "missing-id")
		assert.Nil(t, views)
	})
}

func TestListActiveBans(t *testing.T) {
	t.Parallel()

	t.Run("read-only listing preserves both source types", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, ingestion := openStore(t, path)
		defer store.Close() // nolint:errcheck
		service, err := bans.New(store)

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = ingestion.Process(t.Context(), failed("one"), now)

		require.NoError(t, err)
		_, err = ingestion.Process(t.Context(), failed("two"), now)

		require.NoError(t, err)
		_, err = service.Ban(t.Context(), bans.Request{IP: "203.0.113.1", Duration: time.Hour, Reason: "support"}, now)

		require.NoError(t, err)

		views, err := sqlite.ListActiveBans(t.Context(), path, now)

		require.NoError(t, err)
		require.Len(t, views, 1)
		require.Len(t, views[0].Sources, 2)
		assert.Equal(t, bans.SourceAutomatic, views[0].Sources[0].Kind)
		assert.Equal(t, bans.SourceManual, views[0].Sources[1].Kind)
		assert.Equal(t, "support", views[0].Sources[1].Reason)
	})
}
