package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestStorePrune(t *testing.T) {
	t.Parallel()

	t.Run("retains at least one day of failures", func(t *testing.T) {
		t.Parallel()
		store, processor := openStore(t, filepath.Join(t.TempDir(), "state.db"))
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		now := time.Now().UTC().Truncate(time.Millisecond)
		for _, observation := range []struct {
			id string
			at time.Time
		}{
			{id: "stale", at: now.Add(-25 * time.Hour)},
			{id: "recent", at: now.Add(-23 * time.Hour)},
		} {
			_, err := processor.Process(t.Context(), failed(observation.id), observation.at)
			require.NoError(t, err)
		}
		require.NoError(t, store.Prune(t.Context(), now))

		err := store.Transact(t.Context(), func(tx ingestion.Transaction) error {
			count, err := tx.CountFailures(t.Context(), "203.0.113.1", now.Add(-48*time.Hour))
			assert.Equal(t, 1, count)
			return err
		})
		require.NoError(t, err)
	})

	t.Run("long detection window controls retention", func(t *testing.T) {
		t.Parallel()
		rule := detection.Rule{Threshold: 3, Window: 48 * time.Hour, Ban: time.Minute}
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "state.db"), rule, nil)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		processor, err := ingestion.New(store, rule)
		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		for _, observation := range []struct {
			id string
			at time.Time
		}{
			{id: "stale", at: now.Add(-49 * time.Hour)},
			{id: "within-window", at: now.Add(-30 * time.Hour)},
		} {
			_, err := processor.Process(t.Context(), failed(observation.id), observation.at)
			require.NoError(t, err)
		}
		require.NoError(t, store.Prune(t.Context(), now))

		err = store.Transact(t.Context(), func(tx ingestion.Transaction) error {
			count, err := tx.CountFailures(t.Context(), "203.0.113.1", now.Add(-72*time.Hour))
			assert.Equal(t, 1, count)
			return err
		})
		require.NoError(t, err)
	})
}
