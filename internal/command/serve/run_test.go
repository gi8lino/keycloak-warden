package serve

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/config"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("rejects invalid YAML rule before opening a database", func(t *testing.T) {
		t.Parallel()

		err := Run(
			t.Context(),
			config.Config{},
			"", "127.0.0.1:8081", "",
			"warden.db", "shared", "",
			slog.New(slog.NewJSONHandler(io.Discard, nil)),
			false, false, "test",
		)

		require.ErrorContains(t, err, "threshold")
	})
}

func TestValidateRuntime(t *testing.T) {
	t.Parallel()

	t.Run("accepts required operational settings", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, validateRuntime("127.0.0.1:8081", "", "warden.db", "shared", false))
	})

	t.Run("rejects missing database", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, validateRuntime("127.0.0.1:8081", "", " ", "shared", false), "database")
	})

	t.Run("rejects missing snitch secret", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, validateRuntime("127.0.0.1:8081", "", "warden.db", " ", false), "snitch-secret")
	})

	t.Run("rejects missing listener", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, validateRuntime(" ", "", "warden.db", "shared", false), "listen-address")
	})

	t.Run("metrics require management listener", func(t *testing.T) {
		t.Parallel()

		err := validateRuntime("127.0.0.1:8081", "", "warden.db", "shared", true)
		require.ErrorContains(t, err, "management-listen-address")
	})

	t.Run("metrics allow management listener", func(t *testing.T) {
		t.Parallel()

		err := validateRuntime("127.0.0.1:8081", "127.0.0.1:8082", "warden.db", "shared", true)
		require.NoError(t, err)
	})
}
