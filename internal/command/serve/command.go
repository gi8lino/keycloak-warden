package serve

import (
	"context"
	"io"

	appkitlogging "github.com/containeroo/appkit/logging"
	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// Register adds the serve command and its operational flags to the command tree.
func Register(root *tinyflags.Command, flags appflags.Flags, stdout io.Writer, version string) {
	command := root.Command("serve", "Start authenticated event ingestion and action delivery")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__LISTEN_ADDRESS.")

	managementAddr := command.String(
		"management-listen-address",
		"127.0.0.1:8081",
		"Management HTTP listen address",
	).
		Placeholder("ADDR").
		NotBlank().
		Value()
	path := command.String("config", "warden.yaml", "YAML detection rules and action destinations").
		Placeholder("FILE").
		NotBlank().
		Value()
	database := command.String("database", "warden.db", "SQLite database file").
		NotBlank().
		Value()
	secret := command.String("snitch-secret", "", "Shared key for inbound Snitch signatures").
		Placeholder("SECRET").
		Required().
		NotBlank().
		OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
		Value()
	adminToken := command.String(
		"admin-token",
		"",
		"Bearer token enabling manual-ban API routes on the application listener",
	).
		Placeholder("SECRET").
		OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
		Value()

	logFormat := tinyflags.Enum(command.FlagSet, "log-format", appkitlogging.LogFormatJSON, "Log output format",
		appkitlogging.LogFormatText, appkitlogging.LogFormatJSON).
		Short("l").
		Placeholder("FORMAT").
		Value()
	accessLog := command.Bool("access-log", false, "Enable HTTP request logging").
		Value()
	debug := command.Bool("debug", false, "Enable detailed diagnostic logs").
		Value()
	metricsEnabled := command.Bool("metrics", false, "Expose Prometheus metrics on the management listener").
		Value()

	pruneInterval := command.Duration("prune-interval", maintenance.DefaultPruneInterval, "Interval between SQLite observation cleanup runs").
		Validate(tinyflags.Between(maintenance.MinInterval, maintenance.MaxInterval)).
		Value()
	optimizeInterval := command.Duration("optimize-interval", maintenance.DefaultOptimizeInterval, "Interval between SQLite query planner optimizations").
		Validate(tinyflags.Between(maintenance.MinInterval, maintenance.MaxInterval)).
		Value()

	command.Run(func(ctx context.Context) error {
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}

		logger := appkitlogging.Setup(*logFormat, *debug, stdout)
		logger.Info(
			"starting Keycloak Warden",
			"event", "app_starting",
			"version", version,
		)
		if len(command.Overrides()) > 0 {
			logger.Info(
				"CLI Overrides",
				"event", "cli_overrides",
				"overrides", command.Overrides().Values(),
			)
		}

		return Run(
			ctx,
			cfg,
			*flags.RoutePrefix,
			*flags.ListenAddress,
			*managementAddr,
			*database,
			*secret,
			*adminToken,
			logger,
			*accessLog,
			*metricsEnabled,
			maintenance.Schedule{
				PruneInterval:    *pruneInterval,
				OptimizeInterval: *optimizeInterval,
			},
			version,
		)
	})
}
