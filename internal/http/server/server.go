// Package server composes application routes and independent operational endpoints.
package server

import (
	"log/slog"

	appkithttpserver "github.com/containeroo/appkit/httpserver"

	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
)

// Config supplies HTTP presentation, authentication, and operational dependencies.
type Config struct {
	// AccessLog enables request access logging when true.
	AccessLog bool
	// MetricsEnabled exposes Prometheus metrics and enables request instrumentation.
	MetricsEnabled bool
	// Metrics supplies Prometheus exposition and HTTP request instrumentation when enabled.
	Metrics endpoint.Metrics
	// RoutePrefix is the normalized deployment path, empty at root.
	RoutePrefix string
	// Secret verifies signatures on incoming Snitch events.
	Secret string
	// AdminToken enables and authenticates the administrative API.
	AdminToken string
	// Bans performs validated ban administration.
	Bans endpoint.BanService
	// Logger records request failures and optional access logs.
	Logger *slog.Logger
	// Processor validates and persists authenticated security events.
	Processor endpoint.EventProcessor
	// Readiness checks availability of the persistent store.
	Readiness endpoint.ReadinessProber
	// WorkerDone closes when the action worker stops; nil means the worker is unavailable.
	WorkerDone <-chan struct{}
}

// New constructs two independent handler trees with separate listener lifetimes.
func New(config Config) appkithttpserver.Handlers {
	return appkithttpserver.New(appkithttpserver.Config{
		Application: newApplication(config),
		Management:  newManagement(config),
		RoutePrefix: config.RoutePrefix,
	})
}
