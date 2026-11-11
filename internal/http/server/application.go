package server

import (
	"net/http"

	httpkitmiddleware "github.com/containeroo/httpkit/middleware"

	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
	"github.com/gi8lino/keycloak-warden/internal/http/middleware"
)

// newApplication registers ingestion and authenticated administrative routes.
func newApplication(config Config) http.Handler {
	mux := http.NewServeMux()

	middlewares := []httpkitmiddleware.Middleware{
		middleware.RequestContext(),
	}

	mux.Handle("POST /events", httpkitmiddleware.Chain(
		endpoint.Events(config.Processor, config.Logger, config.Metrics),
		middleware.AuthenticateSnitch(config.Secret),
	))

	// An absent administrator credential disables every administrative route.
	if config.AdminToken != "" && config.BanAdmin != nil {
		guard := middleware.AuthenticateAdmin(config.AdminToken)
		mux.Handle("POST /bans", httpkitmiddleware.Chain(endpoint.CreateBan(config.BanAdmin, config.Logger), guard))
		mux.Handle("GET /bans", httpkitmiddleware.Chain(endpoint.ListBans(config.BanAdmin, config.Logger), guard))
		mux.Handle("GET /bans/{id}", httpkitmiddleware.Chain(endpoint.GetBan(config.BanAdmin, config.Logger), guard))
		mux.Handle("DELETE /bans/{id}", httpkitmiddleware.Chain(endpoint.DeleteBan(config.BanAdmin, config.Logger), guard))
	}

	if config.AdminToken != "" && config.Maintenance != nil {
		guard := middleware.AuthenticateAdmin(config.AdminToken)
		mux.Handle("GET /maintenance", httpkitmiddleware.Chain(endpoint.MaintenanceStatus(config.Maintenance), guard))
		mux.Handle("POST /maintenance/prune", httpkitmiddleware.Chain(endpoint.RunMaintenance(config.Maintenance, config.Logger, "prune"), guard))
		mux.Handle("POST /maintenance/optimize", httpkitmiddleware.Chain(endpoint.RunMaintenance(config.Maintenance, config.Logger, "optimize"), guard))
	}

	if config.AccessLog {
		middlewares = append(middlewares, httpkitmiddleware.AccessLog(
			config.Logger,
			httpkitmiddleware.WithAccessLogFields(
				httpkitmiddleware.LogMethod,
				httpkitmiddleware.LogPath,
				httpkitmiddleware.LogStatus,
				httpkitmiddleware.LogDuration,
				httpkitmiddleware.LogErrorReference,
			),
		))
	}

	middlewares = append(middlewares, middleware.RecoverPanics(config.Logger))

	application := httpkitmiddleware.Chain(mux, middlewares...)

	if config.MetricsEnabled {
		application = config.Metrics.InstrumentHTTP(application)
	}

	return application
}
