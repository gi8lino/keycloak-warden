package serve

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("rejects invalid YAML rule before opening a database", func(t *testing.T) {
		t.Parallel()

		options := testOptions(t)
		options.Config.Rules = nil

		err := Run(t.Context(), options)
		require.ErrorContains(t, err, "configure between one and 64 rules")
		_, statErr := os.Stat(options.Database)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("rejects invalid maintenance before opening a database", func(t *testing.T) {
		t.Parallel()

		options := testOptions(t)
		options.Maintenance.PruneInterval = 0

		err := Run(t.Context(), options)
		require.ErrorContains(t, err, "prune-interval")
		_, statErr := os.Stat(options.Database)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("rejects invalid retry policy before opening a database", func(t *testing.T) {
		t.Parallel()

		options := testOptions(t)
		options.Config.Enforcements.RetryInitialDelay = 20 * time.Second
		options.Config.Enforcements.RetryMaxDelay = 10 * time.Second

		err := Run(t.Context(), options)
		require.ErrorContains(t, err, "retry-max-delay")
		_, statErr := os.Stat(options.Database)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("rejects missing destinations before opening a database", func(t *testing.T) {
		t.Parallel()

		options := testOptions(t)
		options.ObserveOnly = false

		err := Run(t.Context(), options)
		require.ErrorContains(t, err, "automatic ban rules require at least one enforcement destination")
		_, statErr := os.Stat(options.Database)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("releases database after listener startup failure", func(t *testing.T) {
		t.Parallel()

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		options := testOptions(t)
		options.ListenAddress = listener.Addr().String()

		err = Run(t.Context(), options)
		require.ErrorContains(t, err, "address already in use")

		store, err := sqlite.Open(options.Database)
		require.NoError(t, err)
		require.NoError(t, store.Close())
	})
}

// testOptions returns an isolated observe-only server configuration.
func testOptions(t *testing.T) Options {
	t.Helper()

	return Options{
		ListenAddress:           "127.0.0.1:0",
		ManagementListenAddress: "127.0.0.1:0",
		Config: config.Config{
			Rules: detection.Rules{"brute-force": {
				Selector: detection.Selector{
					Kind:   events.KindUser,
					Events: []string{events.TypeLoginError},
				},
				Aggregation: detection.Aggregation{
					GroupBy:   detection.GroupIP,
					Threshold: 2,
					Window:    time.Minute,
				},
				Actions: detection.Actions{
					Ban: time.Minute,
				},
			}},
		},
		ObserveOnly:  true,
		Database:     filepath.Join(t.TempDir(), "warden.db"),
		SnitchSecret: "shared",
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Maintenance: maintenance.Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: 24 * time.Hour,
		},
		Version: "test",
	}
}
