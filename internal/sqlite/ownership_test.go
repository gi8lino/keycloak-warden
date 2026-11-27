package sqlite_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestDatabaseOwnership(t *testing.T) {
	const childPath = "WARDEN_TEST_LOCK_OWNER_PATH"
	if path := os.Getenv(childPath); path != "" {
		store, err := sqlite.Open(path)
		require.NoError(t, err)
		defer store.Close() //nolint:errcheck
		fmt.Println("locked")
		time.Sleep(time.Minute)
		return
	}
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDatabaseOwnership$")
	cmd.Env = append(os.Environ(), childPath+"="+path)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	ready := bufio.NewScanner(stdout)
	require.True(t, ready.Scan())
	require.Equal(t, "locked", ready.Text())
	_, err = sqlite.Open(path)
	require.ErrorContains(t, err, "another Warden instance owns database")
	require.NoError(t, cmd.Process.Kill())
	require.Error(t, cmd.Wait())
	store, err := sqlite.Open(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	store, err = sqlite.Open(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())
}
