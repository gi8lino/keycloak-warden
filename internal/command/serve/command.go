package serve

import (
	"context"
	"io"

	appkitconfig "github.com/containeroo/appkit/config"
	appkitlogging "github.com/containeroo/appkit/logging"
	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

const (
	sectionMaintenance = "Maintenance"
	sectionConfig      = "Configuration"
)

// Register adds the serve command and its operational flags to the command tree.
func Register(root *tinyflags.Command, flags appflags.ServerFlags, stdout io.Writer, version string) {
	command := root.Command("serve", "Start authenticated event ingestion and action delivery")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__LISTEN_ADDRESS.")
	command.NoPositional()
	command.SectionOrder(
		appkitconfig.SectionServer,
		sectionConfig,
		appkitconfig.SectionDatabase,
		appkitconfig.SectionAuthentication,
		sectionMaintenance,
		appkitconfig.SectionLogging,
	)

	managementAddr := command.String(
		"management-listen-address",
		"127.0.0.1:8081",
		"Management HTTP listen address",
	).
		Placeholder("ADDR").
		Section(appkitconfig.SectionServer).
		NotBlank().
		Value()
	path := command.String("config", "warden.yaml", "YAML detection rules and action destinations").
		Placeholder("FILE").
		Section(sectionConfig).
		NotBlank().
		Value()
	database := command.String("database", "warden.db", "SQLite database file").
		Section(appkitconfig.SectionDatabase).
		NotBlank().
		Value()
	secret := command.String("snitch-secret", "", "Shared key for inbound Snitch signatures").
		Section(appkitconfig.SectionAuthentication).
		Placeholder("SECRET").
		Required().
		NotBlank().
		OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
		Value()
	adminToken := command.String(
		"admin-token",
		"",
		"Bearer token enabling administrative API routes on the application listener",
	).
		Placeholder("SECRET").
		Section(appkitconfig.SectionAuthentication).
		OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
		Value()

	logFormat := tinyflags.Enum(command.FlagSet, "log-format", appkitlogging.LogFormatJSON, "Log output format",
		appkitlogging.LogFormatText, appkitlogging.LogFormatJSON).
		Section(appkitconfig.SectionLogging).
		Short("l").
		Placeholder("FORMAT").
		Value()
	accessLog := command.Bool("access-log", false, "Enable HTTP request logging").
		Section(appkitconfig.SectionLogging).
		Value()
	debug := command.Bool("debug", false, "Enable detailed diagnostic logs").
		Section(appkitconfig.SectionLogging).
		Value()
	metricsEnabled := command.Bool("metrics", false, "Expose Prometheus metrics on the management listener").
		Section(appkitconfig.SectionLogging).
		Value()

	pruneInterval := command.Duration("prune-interval", maintenance.DefaultPruneInterval, "Interval between SQLite observation cleanup runs").
		Validate(tinyflags.Between(maintenance.MinInterval, maintenance.MaxInterval)).
		Section(sectionMaintenance).
		Value()
	optimizeInterval := command.Duration("optimize-interval", maintenance.DefaultOptimizeInterval, "Interval between SQLite query planner optimizations").
		Section(sectionMaintenance).
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
