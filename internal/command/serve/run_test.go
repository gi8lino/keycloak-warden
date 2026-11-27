package serve

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("rejects invalid YAML rule before opening a database", func(t *testing.T) {
		t.Parallel()

		err := Run(t.Context(), Options{
			Config:                  config.Config{},
			ListenAddress:           "127.0.0.1:8081",
			ManagementListenAddress: "127.0.0.1:8082",
			Database:                "warden.db",
			SnitchSecret:            "shared",
			Logger:                  slog.New(slog.NewJSONHandler(io.Discard, nil)),
			RetryPolicy:             actions.DefaultRetryPolicy(),
			Maintenance:             maintenance.Schedule{PruneInterval: time.Hour, OptimizeInterval: 24 * time.Hour},
			Version:                 "test",
		})

		require.ErrorContains(t, err, "threshold")
	})
}

func TestRunRejectsInvalidMaintenanceSchedule(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Rule: ingestion.Rule{
			Threshold: 2,
			Window:    time.Minute,
			Ban:       time.Minute,
		},
		Targets: config.Targets{Webhook: map[string]config.WebhookTarget{
			"local": {URL: "http://127.0.0.1:8090/hook"},
		}},
	}
	err := Run(t.Context(), Options{
		Config:                  cfg,
		ListenAddress:           "127.0.0.1:8081",
		ManagementListenAddress: "127.0.0.1:8082",
		Database:                "missing-file.db",
		SnitchSecret:            "shared",
		Logger:                  slog.New(slog.NewJSONHandler(io.Discard, nil)),
		RetryPolicy:             actions.DefaultRetryPolicy(),
		Maintenance:             maintenance.Schedule{PruneInterval: 0, OptimizeInterval: time.Hour},
		Version:                 "test",
	})
	require.ErrorContains(t, err, "prune-interval")
}

func TestRunRejectsInvalidRetryPolicy(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Rule: ingestion.Rule{
			Threshold: 2,
			Window:    time.Minute,
			Ban:       time.Minute,
		},
	}
	path := filepath.Join(t.TempDir(), "warden.db")

	err := Run(t.Context(), Options{
		Config:      cfg,
		ObserveOnly: true,
		Database:    path,
		Maintenance: maintenance.Schedule{
			PruneInterval:    time.Hour,
			OptimizeInterval: 24 * time.Hour,
		},
		RetryPolicy: actions.RetryPolicy{
			InitialDelay: 20 * time.Second,
			MaxDelay:     10 * time.Second,
		},
	})

	require.ErrorContains(t, err, "retry-max-delay")
	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
