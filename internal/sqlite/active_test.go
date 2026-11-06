package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestListActiveBans(t *testing.T) {
	t.Parallel()

	t.Run("read-only listing preserves both source types", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, ingestion := openStore(t, path)
		defer store.Close() //nolint:errcheck
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
