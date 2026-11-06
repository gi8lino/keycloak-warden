package server

import (
	"net/http"

	appkithttpserver "github.com/containeroo/appkit/httpserver"
	httpkitmiddleware "github.com/containeroo/httpkit/middleware"

	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
	"github.com/gi8lino/keycloak-warden/internal/http/middleware"
)

// newManagement exposes health, readiness, and optional metrics on the operational listener.
func newManagement(config Config) http.Handler {
	routes := appkithttpserver.ManagementRoutes{
		Health:    endpoint.Health(),
		Readiness: endpoint.Ready(config.Readiness),
	}
	if config.MetricsEnabled {
		routes.Metrics = config.Metrics.Metrics()
	}

	probes := appkithttpserver.NewManagement(routes)
	return httpkitmiddleware.Chain(probes, middleware.RecoverPanics(config.Logger))
}
