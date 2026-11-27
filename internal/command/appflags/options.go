package appflags

import (
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// ClientOptions returns the configured administrative HTTP client options.
func (flags AdminFlags) ClientOptions() []client.Option {
	return []client.Option{
		client.WithRequestTimeout(*flags.RequestTimeout),
		client.WithMaintenanceTimeout(*flags.MaintenanceTimeout),
		client.WithMaxResponseBytes(*flags.MaxResponseBytes),
	}
}
