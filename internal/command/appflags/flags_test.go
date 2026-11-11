package appflags_test

import (
	"testing"

	"github.com/containeroo/tinyflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
