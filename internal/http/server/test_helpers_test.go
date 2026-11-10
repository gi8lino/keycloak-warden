package server_test

import (
	appkithttpserver "github.com/containeroo/appkit/httpserver"

	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/metrics"
)

// newTestServer supplies a disabled metrics registry unless the test configures one.
func newTestServer(config server.Config) appkithttpserver.Handlers {
	if config.Metrics == nil {
		config.Metrics = metrics.NewRegistry(false, "test")
	}
	return server.New(config)
}
