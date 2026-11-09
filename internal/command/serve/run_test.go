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
			"", "127.0.0.1:8081", "127.0.0.1:8082",
			"warden.db", "shared", "",
			slog.New(slog.NewJSONHandler(io.Discard, nil)),
			false, false, "test",
		)

		require.ErrorContains(t, err, "threshold")
	})
}
