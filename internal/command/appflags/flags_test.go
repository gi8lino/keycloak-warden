package appflags_test

import (
	"testing"

	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplicationURLFlag(t *testing.T) {
	t.Setenv("WARDEN__LISTEN_ADDRESS", ":9080")
	t.Setenv("WARDEN__ROUTE_PREFIX", "/warden")
	cmd := tinyflags.NewCommand("test", tinyflags.ContinueOnError)
	cmd.EnvPrefix("WARDEN_")
	flags := appflags.Register(cmd)
	address := flags.ApplicationURLFlag(cmd.Command("ban", "Ban an IP"))

	t.Run("finalizes omitted flag from server environment", func(t *testing.T) {
		t.Setenv("WARDEN__APPLICATION_URL", "")
		require.NoError(t, cmd.Parse([]string{"ban"}))
		assert.Equal(t, "http://127.0.0.1:9080/warden", *address)
	})

	t.Run("global flags on either side of subcommand override environment", func(t *testing.T) {
		require.NoError(t, cmd.Parse([]string{"--listen-address=[::]:8181", "ban", "--route-prefix=/edge/"}))
		assert.Equal(t, "http://[::1]:8181/edge", *address)
	})

	t.Run("reports invalid shared settings while parsing", func(t *testing.T) {
		t.Setenv("WARDEN__APPLICATION_URL", "")
		t.Setenv("WARDEN__LISTEN_ADDRESS", "missing-port")
		require.ErrorContains(t, cmd.Parse([]string{"ban"}), "--listen-address")
	})

	t.Run("explicit URL takes precedence over environment", func(t *testing.T) {
		t.Setenv("WARDEN__APPLICATION_URL", "https://env.example")
		t.Setenv("WARDEN__LISTEN_ADDRESS", "missing-port")
		require.NoError(t, cmd.Parse([]string{"ban", "--application-url=https://override.example"}))
		assert.Equal(t, "https://override.example", *address)
	})
}
