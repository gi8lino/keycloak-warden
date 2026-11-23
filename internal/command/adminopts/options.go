// Package adminopts adapts parsed administrative flags to HTTP client options.
package adminopts

import (
	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// FromFlags converts the parsed administrative client limits into client options.
func FromFlags(flags appflags.AdminFlags) []client.Option {
	return []client.Option{
		client.WithRequestTimeout(*flags.RequestTimeout),
		client.WithMaintenanceTimeout(*flags.MaintenanceTimeout),
		client.WithMaxResponseBytes(*flags.MaxResponseBytes),
	}
}
