package sqlite_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestMigrate(t *testing.T) {
	t.Parallel()

	t.Run("applies every SQL migration", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)

		entries, err := os.ReadDir("migrations")

		require.NoError(t, err)

		var expected []int
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
				continue
			}

			prefix, _, ok := strings.Cut(entry.Name(), "_")

			require.True(t, ok, "invalid migration filename: %s", entry.Name())
			version, err := strconv.Atoi(prefix)

			require.NoError(t, err, "invalid migration filename: %s", entry.Name())
			expected = append(expected, version)
		}

		require.NotEmpty(t, expected)

		var actual []int
		for version := range migrationHistory(t, db) {
			actual = append(actual, version)
		}

		assert.ElementsMatch(t, expected, actual)
	})

	t.Run("idempotent across reopen", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "test.db")
		migrateTestDatabase(t, path)

		db, err := sql.Open("sqlite", path)

		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, db.Close()) })
		before := migrationHistory(t, db)

		require.NotEmpty(t, before)

		migrateTestDatabase(t, path)

		assert.Equal(t, before, migrationHistory(t, db))
	})

	t.Run("creates failure generation column", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)

		var exists bool
		err := db.QueryRowContext(t.Context(), `
SELECT EXISTS (
    SELECT 1 FROM pragma_table_info('decisions')
    WHERE name = 'failure_generation'
)
`).Scan(&exists)

		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("omits aggregate failure count but preserves observation generation", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)
		var count int
		err := db.QueryRowContext(t.Context(), `
SELECT COUNT(*) FROM pragma_table_info('decisions') WHERE name = 'failures'
`).Scan(&count)
		require.NoError(t, err)
		assert.Zero(t, count)

		err = db.QueryRowContext(t.Context(), `
SELECT COUNT(*) FROM pragma_table_info('decisions') WHERE name = 'failure_generation'
`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		err = db.QueryRowContext(t.Context(), `
SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'failures'
`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("creates ban sources table", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)

		var exists bool
		err := db.QueryRowContext(t.Context(), `
SELECT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = 'ban_sources'
)
`).Scan(&exists)

		require.NoError(t, err)
		assert.True(t, exists)
	})
}

// migrateTestDatabase initializes or reopens a database with the current migrations.
func migrateTestDatabase(t *testing.T, path string) {
	t.Helper()
	rule := detection.Rule{
		Threshold: 2,
		Window:    time.Minute,
		Ban:       time.Minute,
	}
	store, err := sqlite.Open(path, rule, nil)

	require.NoError(t, err)
	require.NoError(t, store.Close())
}

// openMigratedDatabase returns a migrated database for inspection.
func openMigratedDatabase(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	migrateTestDatabase(t, path)
	db, err := sql.Open("sqlite", path)

	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, db.Close()) })
	return db
}

// migrationHistory reads each applied version and its original application timestamp.
func migrationHistory(t *testing.T, db *sql.DB) map[int]int64 {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `
SELECT version, applied_at FROM schema_migrations
`)

	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck

	history := make(map[int]int64)
	for rows.Next() {
		var version int
		var appliedAt int64

		require.NoError(t, rows.Scan(&version, &appliedAt))
		history[version] = appliedAt
	}

	require.NoError(t, rows.Err())
	return history
}

// TestUpgradeLegacyDecision verifies migration 4 retains existing bans, sources, deliveries, and replay generations.
func TestUpgradeLegacyDecision(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "legacy.db")
	old, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	baseline, err := os.ReadFile("migrations/0003_baseline.sql")
	require.NoError(t, err)
	_, err = old.ExecContext(t.Context(), string(baseline))
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Millisecond)
	until := now.Add(time.Hour).UnixMilli()
	_, err = old.ExecContext(t.Context(), `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
INSERT INTO schema_migrations (version, applied_at) VALUES (3, 0);
`)
	require.NoError(t, err)
	_, err = old.ExecContext(t.Context(), `
INSERT INTO decisions (ip, id, revision, active, expires, failures, failure_generation)
VALUES ('203.0.113.10', 'legacy-decision', 4, 1, ?, 5, 3)
`, until)
	require.NoError(t, err)
	_, err = old.ExecContext(t.Context(), `
INSERT INTO ban_sources (ip, kind, expires, reason)
VALUES ('203.0.113.10', 'manual', ?, 'investigation')
`, until)
	require.NoError(t, err)
	_, err = old.ExecContext(t.Context(), `
INSERT INTO deliveries (ip, destination, acknowledged)
VALUES ('203.0.113.10', 'webhook.receiver', 4)
`)
	require.NoError(t, err)
	_, err = old.ExecContext(t.Context(), `
INSERT INTO failures (source, event_id, ip, received, generation)
VALUES ('keycloak', 'event-one', '203.0.113.10', ?, 3)
`, now.UnixMilli())
	require.NoError(t, err)
	require.NoError(t, old.Close())

	store, err := sqlite.Open(path, detection.Rule{
		Threshold: 2,
		Window:    time.Minute,
		Ban:       time.Minute,
	}, []string{"webhook.receiver"})
	require.NoError(t, err)
	record, err := store.GetDecision(t.Context(), "legacy-decision", now)
	require.NoError(t, err)
	assert.Equal(t, int64(4), record.Decision.Revision)
	assert.Len(t, record.Sources, 1)
	assert.Equal(t, "investigation", record.Sources[0].Reason)
	assert.Len(t, record.Deliveries, 1)
	assert.Equal(t, int64(4), record.Deliveries[0].Revision)
	require.NoError(t, store.Close())

	upgraded, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	var generation, events, legacyColumn int
	require.NoError(t, upgraded.QueryRowContext(t.Context(), `SELECT failure_generation FROM decisions WHERE id = 'legacy-decision'`).Scan(&generation))
	require.NoError(t, upgraded.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM failures WHERE event_id = 'event-one'`).Scan(&events))
	require.NoError(t, upgraded.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('decisions') WHERE name = 'failures'`).Scan(&legacyColumn))
	assert.Equal(t, 3, generation)
	assert.Equal(t, 1, events)
	assert.Zero(t, legacyColumn)
	var applied int
	require.NoError(t, upgraded.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM schema_migrations WHERE version = 4`).Scan(&applied))
	assert.Equal(t, 1, applied)
	require.NoError(t, upgraded.Close())

	// Opening an already upgraded database should never rerun the migration.
	reopened, err := sqlite.Open(path, detection.Rule{
		Threshold: 2,
		Window:    time.Minute,
		Ban:       time.Minute,
	}, []string{"webhook.receiver"})
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}
