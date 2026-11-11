package serve

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
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
			false, false, maintenance.Schedule{PruneInterval: time.Hour, OptimizeInterval: 24 * time.Hour}, "test",
		)

		require.ErrorContains(t, err, "threshold")
	})
}

func TestRunRejectsInvalidMaintenanceSchedule(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Rule: detection.Rule{
			Threshold: 2,
			Window:    time.Minute,
			Ban:       time.Minute,
		},
		Targets: config.Targets{Webhook: map[string]config.WebhookTarget{
			"local": {URL: "http://127.0.0.1:8090/hook"},
		}},
	}
	err := Run(
		t.Context(),
		cfg,
		"", "127.0.0.1:8081", "127.0.0.1:8082",
		"missing-file.db", "shared", "",
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		false, false, maintenance.Schedule{PruneInterval: 0, OptimizeInterval: time.Hour}, "test",
	)
	require.ErrorContains(t, err, "prune-interval")
}
