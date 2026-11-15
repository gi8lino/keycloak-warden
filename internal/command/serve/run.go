package serve

import (
	"context"
	"errors"
	"log/slog"

	"github.com/containeroo/appkit/httpserver"
	"github.com/containeroo/httpkit/grace"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/bootstrap"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/metrics"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Options describes the resolved operational settings for one Warden server instance.
type Options struct {
	// Config contains the detection rule and destination configuration.
	Config config.Config
	// RoutePrefix is prepended to application endpoints, but not management endpoints.
	RoutePrefix string
	// ListenAddress selects the application HTTP listener.
	ListenAddress string
	// ManagementListenAddress selects the management HTTP listener.
	ManagementListenAddress string
	// Database is the SQLite database path.
	Database string
	// SnitchSecret authenticates incoming Keycloak Snitch events.
	SnitchSecret string
	// AdminToken enables and authenticates administrative endpoints when set.
	AdminToken string
	// Logger handles Warden operational diagnostics.
	Logger *slog.Logger
	// AccessLog enables application HTTP access logging.
	AccessLog bool
	// MetricsEnabled enables management metrics and instrumentation.
	MetricsEnabled bool
	// Maintenance configures observation pruning and SQLite optimization.
	Maintenance maintenance.Schedule
	// Version labels the running build in metrics.
	Version string
}

// Run starts Warden using resolved configuration and separate operational options.
func Run(parent context.Context, options Options) error {
	cfg := options.Config
	schedule := options.Maintenance
	logger := options.Logger
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := schedule.Validate(); err != nil {
		return err
	}
	destinations, names, err := bootstrap.Destinations(cfg.Targets)
	if err != nil {
		return err
	}

	store, err := sqlite.Open(options.Database)
	if err != nil {
		return err
	}
	defer store.Close() //nolint:errcheck

	if err := actions.ValidateTargets(parent, store, names); err != nil {
		return err
	}
	if err := actions.ReconcileTargets(parent, store, destinations); err != nil {
		return err
	}

	processor, err := ingestion.New(store, cfg.Rule, names)
	if err != nil {
		return err
	}
	banAdmin, err := bans.NewAdminService(store, names)
	if err != nil {
		return err
	}
	expirer, err := bans.NewExpiryService(store, names)
	if err != nil {
		return err
	}

	registry := metrics.NewRegistry(options.MetricsEnabled, options.Version)
	for name, target := range destinations {
		target.Provider = registry.InstrumentProvider(name, target.Provider)
		destinations[name] = target
	}

	ctx, stop := grace.SignalContext(parent)
	defer stop()

	maintenanceRunner := maintenance.Start(ctx, store, schedule, max(maintenance.MinObservationRetention, cfg.Rule.Window), logger)
	runner := actions.Start(ctx, store, expirer, destinations, logger)
	handlers := server.New(server.Config{
		AccessLog:      options.AccessLog,
		MetricsEnabled: options.MetricsEnabled,
		Metrics:        registry,
		RoutePrefix:    options.RoutePrefix,
		Secret:         options.SnitchSecret,
		AdminToken:     options.AdminToken,
		BanAdmin:       banAdmin,
		Maintenance:    maintenanceRunner,
		Logger:         logger,
		Processor:      processor,
		Readiness:      store,
		WorkerDone:     runner.Done(),
	})

	// The server owns the blocking lifecycle; stop the worker before closing SQLite.
	err = httpserver.Run(
		ctx,
		options.ListenAddress,
		options.ManagementListenAddress,
		handlers,
		logger.With("server", "application"),
		logger.With("server", "management"),
	)

	workerErr := runner.Close()
	maintenanceRunner.Close()

	return errors.Join(err, workerErr)
}
