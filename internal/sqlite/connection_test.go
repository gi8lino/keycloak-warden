package sqlite

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionReplacementPreservesPragmas(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "warden.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	// Force database/sql to open a new physical connection on every acquisition.
	store.db.SetMaxIdleConns(0)
	var foreignKeys, busyTimeout int
	require.NoError(t, store.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys))
	require.Equal(t, 1, foreignKeys)
	require.NoError(t, store.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout))
	require.Equal(t, 5000, busyTimeout)
}
