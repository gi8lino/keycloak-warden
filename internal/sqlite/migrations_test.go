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
	rule := detection.Rule{Threshold: 2, Window: time.Minute, Ban: time.Minute}
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
