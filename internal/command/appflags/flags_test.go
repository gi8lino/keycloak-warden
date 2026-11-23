package appflags_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/containeroo/tinyflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
)

// adminCommand registers one administrative command against shared server defaults.
func adminCommand() (*tinyflags.Command, appflags.AdminFlags) {
	root := tinyflags.NewCommand("test", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	server := appflags.RegisterServer(root)
	admin := appflags.RegisterAdmin(root.Command("ban", "Ban an IP"), server)
	return root, admin
}

func TestRegisterAdmin(t *testing.T) {
	t.Run("derives omitted URL from shared server environment", func(t *testing.T) {
		t.Setenv("WARDEN__LISTEN_ADDRESS", ":9080")
		t.Setenv("WARDEN__ROUTE_PREFIX", "/warden")
		t.Setenv("WARDEN__APPLICATION_URL", "")

		root, admin := adminCommand()
		require.NoError(t, root.Parse([]string{"ban"}))
		assert.Equal(t, "http://127.0.0.1:9080/warden", *admin.ApplicationURL)
	})

	t.Run("global flags on either side of command override environment", func(t *testing.T) {
		t.Setenv("WARDEN__LISTEN_ADDRESS", ":9080")
		t.Setenv("WARDEN__ROUTE_PREFIX", "/warden")

		root, admin := adminCommand()
		require.NoError(t, root.Parse([]string{"--listen-address=[::]:8181", "ban", "--route-prefix=/edge/"}))
		assert.Equal(t, "http://[::1]:8181/edge", *admin.ApplicationURL)
	})

	t.Run("reports invalid server listen address while parsing", func(t *testing.T) {
		t.Setenv("WARDEN__LISTEN_ADDRESS", "missing-port")
		t.Setenv("WARDEN__APPLICATION_URL", "")

		root, _ := adminCommand()
		require.ErrorContains(t, root.Parse([]string{"ban"}), "--listen-address")
	})

	t.Run("explicit URL takes precedence over invalid server address", func(t *testing.T) {
		t.Setenv("WARDEN__LISTEN_ADDRESS", "missing-port")
		t.Setenv("WARDEN__APPLICATION_URL", "https://env.example")

		root, admin := adminCommand()
		require.NoError(t, root.Parse([]string{"ban", "--application-url=https://override.example"}))
		assert.Equal(t, "https://override.example", *admin.ApplicationURL)
	})

	t.Run("rejects insecure remote administration URL", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.ErrorContains(t, root.Parse([]string{"ban", "--application-url=http://warden.example"}), "HTTPS")
	})

	t.Run("registers administrator token from environment", func(t *testing.T) {
		t.Setenv("WARDEN__ADMIN_TOKEN", "environment-secret")

		root, admin := adminCommand()
		require.NoError(t, root.Parse([]string{"ban"}))
		assert.Equal(t, "environment-secret", *admin.AdminToken)
	})

	t.Run("explicit administrator token overrides environment", func(t *testing.T) {
		t.Setenv("WARDEN__ADMIN_TOKEN", "environment-secret")

		root, admin := adminCommand()
		require.NoError(t, root.Parse([]string{"ban", "--admin-token=flag-secret"}))
		assert.Equal(t, "flag-secret", *admin.AdminToken)
	})
}

// TestAdminClientSettings checks the HTTP client limits exposed as CLI values.
func TestAdminClientSettings(t *testing.T) {
	t.Parallel()

	t.Run("uses the administration client defaults", func(t *testing.T) {
		t.Parallel()

		root, flags := adminCommand()
		require.NoError(t, root.Parse([]string{"ban"}))

		assert.Equal(t, adminclient.DefaultRequestTimeout, *flags.RequestTimeout)
		assert.Equal(t, adminclient.DefaultMaintenanceTimeout, *flags.MaintenanceTimeout)
		assert.Equal(t, adminclient.DefaultMaxResponseBytes, *flags.MaxResponseBytes)
	})

	t.Run("parses all three positive overrides", func(t *testing.T) {
		t.Parallel()

		root, flags := adminCommand()
		require.NoError(t, root.Parse([]string{
			"ban",
			"--request-timeout=2s",
			"--maintenance-timeout=1m",
			"--max-response-bytes=2048",
		}))

		assert.Equal(t, 2*time.Second, *flags.RequestTimeout)
		assert.Equal(t, time.Minute, *flags.MaintenanceTimeout)
		assert.Equal(t, 2048, *flags.MaxResponseBytes)
	})

	t.Run("rejects zero ordinary request timeout", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.Error(t, root.Parse([]string{"ban", "--request-timeout=0s"}))
	})

	t.Run("rejects negative ordinary request timeout", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.Error(t, root.Parse([]string{"ban", "--request-timeout=-1s"}))
	})

	t.Run("rejects zero maintenance timeout", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.Error(t, root.Parse([]string{"ban", "--maintenance-timeout=0s"}))
	})

	t.Run("rejects negative maintenance timeout", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.Error(t, root.Parse([]string{"ban", "--maintenance-timeout=-1s"}))
	})

	t.Run("rejects zero response limit", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.Error(t, root.Parse([]string{"ban", "--max-response-bytes=0"}))
	})

	t.Run("rejects negative response limit", func(t *testing.T) {
		t.Parallel()

		root, _ := adminCommand()
		require.Error(t, root.Parse([]string{"ban", "--max-response-bytes=-1"}))
	})

	t.Run("rejects a response limit that would overflow the read sentinel", func(t *testing.T) {
		t.Parallel()

		if int64(math.MaxInt) != math.MaxInt64 {
			t.Skip("int cannot represent MaxInt64")
		}

		root, _ := adminCommand()
		err := root.Parse([]string{"ban", fmt.Sprintf("--max-response-bytes=%d", math.MaxInt)})

		require.ErrorContains(t, err, "less than MaxInt64")
	})
}
