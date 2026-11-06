package serve

import (
	"context"
	"io"

	appkitlogging "github.com/containeroo/appkit/logging"
	"github.com/containeroo/httpkit/prefix"
	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/config"
)

// Register adds the serve command and its operational flags to the command tree.
func Register(root *tinyflags.Command, stdout io.Writer, version string) {
	command := root.Command("serve", "Start authenticated event ingestion and action delivery")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__LISTEN_ADDRESS.")

	path := command.String("config", "warden.yaml", "YAML detection rules and action destinations").
		Placeholder("FILE").Value()
	database := command.String("database", "warden.db", "SQLite database file").
		Value()
	secret := command.String("snitch-secret", "", "Shared key for inbound Snitch signatures").
		Placeholder("SECRET").
		OverriddenValueMaskFn(tinyflags.MaskFirstLast).
		Value()
	adminToken := command.String(
		"admin-token",
		"",
		"Bearer token enabling manual-ban API routes on the application listener",
	).
		Placeholder("SECRET").
		OverriddenValueMaskFn(tinyflags.MaskFirstLast).
		Value()

	routePrefix := command.String("route-prefix", "", "URL path prefix under which the application is served").
		Validate(prefix.ValidateRoutePrefix).
		Finalize(prefix.NormalizeRoutePrefix).
		Value()
	listenAddr := command.String("listen-address", "127.0.0.1:8080", "Public event listener address").
		Placeholder("ADDR").
		Value()
	managementAddr := command.String(
		"management-listen-address",
		"127.0.0.1:8081",
		"Management listener address; empty disables it",
	).
		Placeholder("ADDR").
		Value()

	logFormat := tinyflags.Enum(command.FlagSet, "log-format", appkitlogging.LogFormatJSON, "Log output format",
		appkitlogging.LogFormatText, appkitlogging.LogFormatJSON).
		Short("l").
		Placeholder("FORMAT").
		Value()
	accessLog := command.Bool("access-log", false, "Enable HTTP request logging").
		Value()

	metricsEnabled := command.Bool("metrics", false, "Expose Prometheus metrics on the management listener").
		Value()

	command.Run(func(ctx context.Context) error {
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}

		logger := appkitlogging.Setup(*logFormat, false, stdout)

		return Run(
			ctx,
			cfg,
			*routePrefix,
			*listenAddr,
			*managementAddr,
			*database,
			*secret,
			*adminToken,
			logger,
			*accessLog,
			*metricsEnabled,
			version,
		)
	})
}
