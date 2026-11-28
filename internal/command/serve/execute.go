package serve

import (
	"context"
	"errors"
	"time"

	"github.com/containeroo/appkit/httpserver"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/internal/bootstrap"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/metrics"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// execute constructs services and runs HTTP listeners with their background workers.
func execute(
	ctx context.Context,
	options Options,
	store *sqlite.Store,
	policy bans.Policy,
	destinations map[string]enforcement.Target,
	names []string,
	notificationTargets map[string]notifications.Target,
) (err error) {
	logger := options.Logger

	processor, err := ingestion.New(store, options.Config.Rules.Ordered(), names, policy)
	if err != nil {
		return err
	}

	banAdmin, err := bans.NewAdminService(store, names, policy)
	if err != nil {
		return err
	}

	overviewService, err := overview.NewService(store)
	if err != nil {
		return err
	}

	retryService, err := enforcement.NewRetryService(store, names)
	if err != nil {
		return err
	}

	expirer, err := bans.NewExpiryService(store, names)
	if err != nil {
		return err
	}

	if err := prepareDestinations(ctx, store, policy, destinations, names, notificationTargets); err != nil {
		return err
	}

	registry := metrics.NewRegistry(options.MetricsEnabled, options.Version)
	for name, target := range destinations {
		target.Provider = registry.InstrumentProvider(name, target.Provider)
		destinations[name] = target
	}

	for name, target := range notificationTargets {
		target.Provider = registry.InstrumentNotificationProvider(name, target.Provider)
		notificationTargets[name] = target
	}

	maintenanceRunner := maintenance.Start(ctx, store, options.Maintenance, maintenance.Retention{
		Observations: max(maintenance.MinObservationRetention, options.Config.ObservationWindow()),
		Incidents:    options.IncidentRetention,
	}, logger)
	defer maintenanceRunner.Close()

	runner := enforcement.Start(ctx, store, expirer, destinations, options.Config.Enforcements.RetryPolicy(), logger)
	defer func() {
		err = errors.Join(err, runner.Close())
	}()

	var notificationDone <-chan struct{}
	var notificationSnapshot overview.RuntimeSnapshot
	if len(notificationTargets) > 0 {
		notifier := notifications.Start(ctx, store, notificationTargets, options.Config.Notifications.RetryPolicy(), logger)
		defer notifier.Close()
		notificationDone = notifier.Done()
		notificationSnapshot = notifier
	}

	handlers := server.New(server.Config{
		AccessLog:         options.AccessLog,
		MetricsEnabled:    options.MetricsEnabled,
		Metrics:           registry,
		RoutePrefix:       options.RoutePrefix,
		Secret:            options.SnitchSecret,
		AdminToken:        options.AdminToken,
		BanAdmin:          banAdmin,
		Overview:          overviewService,
		Retry:             retryService,
		Operations:        overviewService,
		Maintenance:       maintenanceRunner,
		Notifications:     overview.NewNotificationService(store),
		NotificationRetry: notifications.NewRetryService(store, notificationTargets),
		Workers:           overview.NewWorkerService(runner, notificationSnapshot, maintenanceRunner, store),
		Logger:            logger,
		Processor:         processor,
		Readiness:         store,
		EnforcementDone:   runner.Done(),
		NotificationDone:  notificationDone,
	})

	return httpserver.Run(
		ctx,
		options.ListenAddress,
		options.ManagementListenAddress,
		handlers,
		logger.With("server", "application"),
		logger.With("server", "management"),
	)
}

// prepareDestinations checks persisted obligations before reconciling configured targets.
func prepareDestinations(
	ctx context.Context,
	store *sqlite.Store,
	policy bans.Policy,
	destinations map[string]enforcement.Target,
	names []string,
	notificationTargets map[string]notifications.Target,
) error {
	if err := bootstrap.ValidateAdmission(ctx, store, policy, time.Now()); err != nil {
		return err
	}

	if err := enforcement.ValidateTargets(ctx, store, names); err != nil {
		return err
	}

	identities := make(map[string]string, len(destinations))
	for name, target := range destinations {
		identities[name] = target.Identity
	}
	notificationIdentities := make(map[string]string, len(notificationTargets))
	for name, target := range notificationTargets {
		notificationIdentities[name] = target.Identity
	}
	return store.ConfigureDestinations(ctx, identities, notificationIdentities, func(reconciler enforcement.AttemptLimitReconciler) error {
		return enforcement.ReconcileTargets(ctx, reconciler, destinations)
	})
}
