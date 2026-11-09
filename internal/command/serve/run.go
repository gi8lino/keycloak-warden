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
	"github.com/gi8lino/keycloak-warden/internal/metrics"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Run starts Warden with YAML configuration and separate operational settings.
func Run(
	parent context.Context,
	cfg config.Config,
	routePrefix, listen, managementListen, database, secret, adminToken string,
	logger *slog.Logger,
	accessLog, metricsEnabled bool,
	version string,
) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	destinations, names, err := bootstrap.Destinations(cfg.Targets)
	if err != nil {
		return err
	}

	store, err := sqlite.Open(database, cfg.Rule, names)
	if err != nil {
		return err
	}
	defer store.Close() //nolint:errcheck

	processor, err := ingestion.New(store, cfg.Rule)
	if err != nil {
		return err
	}
	banService, err := bans.New(store)
	if err != nil {
		return err
	}

	registry := metrics.NewRegistry(metricsEnabled, version)
	for name, destination := range destinations {
		destinations[name] = registry.InstrumentProvider(name, destination)
	}

	ctx, stop := grace.SignalContext(parent)
	defer stop()

	runner := actions.Start(ctx, store, destinations, logger)
	handlers := server.New(server.Config{
		AccessLog:      accessLog,
		MetricsEnabled: metricsEnabled,
		Metrics:        registry,
		RoutePrefix:    routePrefix,
		Secret:         secret,
		AdminToken:     adminToken,
		Bans:           banService,
		Logger:         logger,
		Processor:      processor,
		Readiness:      store,
		WorkerDone:     runner.Done(),
	})

	// The server owns the blocking lifecycle; stop the worker before closing SQLite.
	err = httpserver.Run(
		ctx,
		listen,
		managementListen,
		handlers,
		logger.With("server", "application"),
		logger.With("server", "management"),
	)

	return errors.Join(err, runner.Close())
}
