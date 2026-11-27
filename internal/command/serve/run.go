package serve

import (
	"context"
	"errors"
	"log/slog"

	"github.com/containeroo/httpkit/grace"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/bootstrap"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Options describes the resolved operational settings for one Warden server instance.
type Options struct {
	// ListenAddress selects the application HTTP listener.
	ListenAddress string
	// ManagementListenAddress selects the management HTTP listener.
	ManagementListenAddress string
	// Config contains detection rules and destination configuration.
	Config config.Config
	// ObserveOnly records hypothetical bans without invoking enforcement providers.
	ObserveOnly bool
	// RoutePrefix is prepended to application endpoints, but not management endpoints.
	RoutePrefix string
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

// Validate checks operational settings before opening the database.
func (o Options) Validate() error {
	if err := o.Config.Validate(); err != nil {
		return err
	}
	return o.Maintenance.Validate()
}

// Run prepares the server dependencies and owns the database lifecycle.
func Run(parent context.Context, options Options) (err error) {
	if err := options.Validate(); err != nil {
		return err
	}

	protection, err := bans.NewProtection(options.Config.ProtectedIPs)
	if err != nil {
		return err
	}
	policy := bans.Policy{
		Protection:  protection,
		ObserveOnly: options.ObserveOnly,
	}

	var destinations map[string]enforcement.Target
	var names []string
	if !options.ObserveOnly {
		destinations, names, err = bootstrap.Destinations(options.Config.Enforcements)
		if err != nil {
			return err
		}
		if options.Config.Rules.RequiresEnforcement() && len(names) == 0 {
			return errors.New("automatic ban rules require at least one enforcement destination")
		}
	}

	notificationTargets, err := bootstrap.Notifications(options.Config.Notifications)
	if err != nil {
		return err
	}

	ctx, stop := grace.SignalContext(parent)
	defer stop()

	store, err := sqlite.Open(options.Database)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, store.Close())
	}()

	return execute(ctx, options, store, policy, destinations, names, notificationTargets)
}
