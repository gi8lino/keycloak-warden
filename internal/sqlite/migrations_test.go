package sqlite_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

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

	t.Run("defines the desired state as constrained text", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)
		var columnType, defaultValue string
		err := db.QueryRowContext(t.Context(), `
SELECT type, dflt_value FROM pragma_table_info('decisions') WHERE name = 'state'
`).Scan(&columnType, &defaultValue)

		require.NoError(t, err)
		assert.Equal(t, "TEXT", columnType)
		assert.Equal(t, "'unbanned'", defaultValue)

		var oldColumnCount int
		err = db.QueryRowContext(t.Context(), `
SELECT COUNT(*) FROM pragma_table_info('decisions') WHERE name = 'active'
`).Scan(&oldColumnCount)

		require.NoError(t, err)
		assert.Zero(t, oldColumnCount)
	})

	t.Run("rejects unsupported decision state values", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)
		_, err := db.ExecContext(t.Context(), `
INSERT INTO decisions (ip, id, revision, state, expires)
VALUES ('192.0.2.80', 'invalid-state', 0, 'invalid', 0)
`)

		require.ErrorContains(t, err, "CHECK constraint failed")
	})

	t.Run("defaults new decisions to unbanned", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)
		_, err := db.ExecContext(t.Context(), `
INSERT INTO decisions (ip, id, revision, expires)
VALUES ('192.0.2.81', 'default-state', 0, 0)
`)
		require.NoError(t, err)

		var state string
		err = db.QueryRowContext(t.Context(), `
SELECT state FROM decisions WHERE ip = '192.0.2.81'
`).Scan(&state)

		require.NoError(t, err)
		assert.Equal(t, "unbanned", state)
	})

	t.Run("indexes decision state and expiry", func(t *testing.T) {
		t.Parallel()

		db := openMigratedDatabase(t)
		rows, err := db.QueryContext(t.Context(), `
SELECT name FROM pragma_index_info('expiry') ORDER BY seqno
`)
		require.NoError(t, err)
		defer rows.Close() //nolint:errcheck

		var columns []string
		for rows.Next() {
			var name string
			require.NoError(t, rows.Scan(&name))
			columns = append(columns, name)
		}
		require.NoError(t, rows.Err())
		assert.Equal(t, []string{"state", "expires"}, columns)
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
	store, err := sqlite.Open(path)

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

// TestMigrateRejectsNewerDatabase protects stores created by future releases.
func TestMigrateRejectsNewerDatabase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "test.db")
	migrateTestDatabase(t, path)

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO schema_migrations (version, applied_at) VALUES (999, 0)")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	store, err := sqlite.Open(path)
	if store != nil {
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
	}
	require.ErrorContains(t, err, "newer than supported version")
}
