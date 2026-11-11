package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

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

	rule := detection.Rule{
		Threshold: 2,
		Window:    time.Minute,
		Ban:       time.Minute,
	}
	store, err := sqlite.Open(path, rule, nil)
	if store != nil {
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
	}
	require.ErrorContains(t, err, "newer than supported version")
}
