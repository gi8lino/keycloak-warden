// Package appflags defines shared server and administrative client flags.
package appflags

import (
	"fmt"
	"net"
	"net/url"

	appkitconfig "github.com/containeroo/appkit/config"
	"github.com/containeroo/httpkit/prefix"
	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

const sectionAdminAPI = "Administration API"

// ServerFlags holds the global application listener settings parsed by tinyflags.
type ServerFlags struct {
	// ListenAddress identifies the application interface and port.
	ListenAddress *string
	// RoutePrefix is the normalized base path of the application API.
	RoutePrefix *string
}

// AdminFlags holds the authenticated application API settings for an administrative command.
type AdminFlags struct {
	// ApplicationURL identifies the application API endpoint.
	ApplicationURL *string
	// AdminToken authenticates requests to the administrative API.
	AdminToken *string
}

// RegisterServer registers application listener settings on the root command.
func RegisterServer(root *tinyflags.Command) ServerFlags {
	return ServerFlags{
		ListenAddress: root.Globals().String("listen-address", "127.0.0.1:8080", "Application listener address").
			NotBlank().
			Section(appkitconfig.SectionServer).
			Placeholder("ADDR").
			Value(),
		RoutePrefix: root.Globals().String("route-prefix", "", "Application API route prefix").
			Section(appkitconfig.SectionServer).
			Validate(prefix.ValidateRoutePrefix).
			Finalize(prefix.NormalizeRoutePrefix).
			Value(),
	}
}

// RegisterAdmin registers client settings and derives the default URL from server flags.
func RegisterAdmin(cmd *tinyflags.Command, server ServerFlags) AdminFlags {
	flags := AdminFlags{
		ApplicationURL: cmd.String("application-url", "", "Override the URL derived from --listen-address and --route-prefix").
			Section(sectionAdminAPI).
			Value(),
		AdminToken: cmd.String("admin-token", "", "Application API administrator bearer token").
			Section(sectionAdminAPI).
			Placeholder("SECRET").
			OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
			Value(),
	}

	cmd.Validate(func() error {
		if *flags.ApplicationURL == "" {
			host, port, err := net.SplitHostPort(*server.ListenAddress)
			if err != nil {
				return fmt.Errorf("invalid --listen-address: %w", err)
			}
			base := url.URL{
				Scheme: "http",
				Host:   net.JoinHostPort(connectHost(host), port),
				Path:   *server.RoutePrefix,
			}
			*flags.ApplicationURL = base.String()
		}
		return client.ValidateURL(*flags.ApplicationURL)
	})
	return flags
}

// connectHost substitutes a reachable loopback address for a wildcard bind.
func connectHost(host string) string {
	if host == "" {
		return "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return host
}
