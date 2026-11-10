package sqlite

import (
	"database/sql"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baselineFixture returns historical migrations for exercising baseline upgrades.
func baselineFixture() fstest.MapFS {
	return fstest.MapFS{
		"migrations/0001_initial.sql": &fstest.MapFile{Data: []byte(`
CREATE TABLE samples (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO samples (id, value) VALUES (1, 'first');
`)},
		"migrations/0002_index.sql": &fstest.MapFile{Data: []byte(`
CREATE INDEX samples_by_value ON samples(value);
`)},
	}
}

// replacementFixture returns the equivalent baseline plus a later migration.
func replacementFixture() fstest.MapFS {
	return fstest.MapFS{
		"migrations/0003_baseline.sql": &fstest.MapFile{Data: []byte(`
-- Consolidated schema and initial rows.
-- warden:replaces-through=2
CREATE TABLE samples (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO samples (id, value) VALUES (1, 'first');
CREATE INDEX samples_by_value ON samples(value);
`)},
		"migrations/0004_extra.sql": &fstest.MapFile{Data: []byte(`
CREATE TABLE extra (id INTEGER PRIMARY KEY);
`)},
	}
}

// baselineDatabase opens a single-connection SQLite test database.
func baselineDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { assert.NoError(t, db.Close()) })
	return db
}

func TestMigrationBaseline(t *testing.T) {
	t.Parallel()

	t.Run("fresh database applies consolidated baseline and later migration", func(t *testing.T) {
		t.Parallel()
		db := baselineDatabase(t)
		require.NoError(t, migrateFrom(t.Context(), db, replacementFixture()))
		var value string
		require.NoError(t, db.QueryRow("SELECT value FROM samples WHERE id = 1").Scan(&value))
		assert.Equal(t, "first", value)
		var count int
		require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count))
		assert.Equal(t, 2, count) // versions 3 and 4
	})

	t.Run("existing database skips baseline SQL but preserves its records", func(t *testing.T) {
		t.Parallel()
		db := baselineDatabase(t)
		require.NoError(t, migrateFrom(t.Context(), db, baselineFixture()))
		_, err := db.Exec("INSERT INTO samples (id, value) VALUES (2, 'live data')")
		require.NoError(t, err)

		require.NoError(t, migrateFrom(t.Context(), db, replacementFixture()))
		require.NoError(t, migrateFrom(t.Context(), db, replacementFixture())) // idempotent

		var value string
		require.NoError(t, db.QueryRow("SELECT value FROM samples WHERE id = 2").Scan(&value))
		assert.Equal(t, "live data", value)
		var count int
		require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count))
		assert.Equal(t, 4, count) // historical 1, 2, adopted 3, and newer 4
	})

	t.Run("incomplete historical database cannot silently adopt baseline", func(t *testing.T) {
		t.Parallel()
		db := baselineDatabase(t)
		old := baselineFixture()
		delete(old, "migrations/0002_index.sql")
		require.NoError(t, migrateFrom(t.Context(), db, old))

		err := migrateFrom(t.Context(), db, replacementFixture())
		require.ErrorContains(t, err, "must be upgraded to 2")
		var count int
		require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count))
		assert.Equal(t, 1, count)
	})

	t.Run("invalid baseline marker fails before touching database", func(t *testing.T) {
		t.Parallel()
		db := baselineDatabase(t)
		bad := replacementFixture()
		bad["migrations/0003_baseline.sql"] = &fstest.MapFile{Data: []byte(`-- warden:replaces-through=1
CREATE TABLE samples (id INTEGER PRIMARY KEY);
`)}
		err := migrateFrom(t.Context(), db, bad)
		require.ErrorContains(t, err, "baseline must replace through version 2")
	})
}
