// Package appflags defines shared server and administrative client flags.
package appflags

import (
	"errors"
	"net"
	"net/url"
	"time"

	appkitconfig "github.com/containeroo/appkit/config"
	"github.com/containeroo/httpkit/prefix"
	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// sectionAdminAPI groups administrative connection flags in command help.
const sectionAdminAPI = "Administration API"

// ServerFlags holds the global application listener settings parsed by tinyflags.
type ServerFlags struct {
	// ListenAddress identifies the application interface and port.
	ListenAddress *net.TCPAddr
	// RoutePrefix is the normalized base path of the application API.
	RoutePrefix string
}

// AdminFlags holds the authenticated application API settings for an administrative command.
type AdminFlags struct {
	// ApplicationURL identifies the application API endpoint.
	ApplicationURL *string
	// AdminToken authenticates requests to the administrative API.
	AdminToken *string
	// RequestTimeout bounds ordinary administrative HTTP requests.
	RequestTimeout *time.Duration
	// MaintenanceTimeout bounds database maintenance HTTP requests.
	MaintenanceTimeout *time.Duration
	// MaxResponseBytes limits successful administrative response bodies.
	MaxResponseBytes *int
}

// RegisterServer registers application listener settings on the root command.
func RegisterServer(root *tinyflags.Command) *ServerFlags {
	flags := &ServerFlags{}

	root.Globals().TCPAddrVar(&flags.ListenAddress, "listen-address", &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 8080,
	}, "Application listener address").
		Validate(ValidateListenAddress).
		Section(appkitconfig.SectionServer).
		Placeholder("ADDR")

	root.Globals().StringVar(&flags.RoutePrefix, "route-prefix", "", "Application API route prefix").
		Section(appkitconfig.SectionServer).
		Validate(prefix.ValidateRoutePrefix).
		Finalize(prefix.NormalizeRoutePrefix)

	return flags
}

// RegisterAdmin registers client settings and derives the default URL from server flags.
func RegisterAdmin(cmd *tinyflags.Command, server *ServerFlags) AdminFlags {
	flags := AdminFlags{
		ApplicationURL: cmd.String("application-url", "", "Override the URL derived from --listen-address and --route-prefix").
			Section(sectionAdminAPI).
			Placeholder("URL").
			Value(),
		AdminToken: cmd.String("admin-token", "", "Application API administrator bearer token").
			Section(sectionAdminAPI).
			Placeholder("SECRET").
			OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
			Value(),
		RequestTimeout: cmd.Duration("request-timeout", client.DefaultRequestTimeout, "Timeout for ordinary administrative HTTP requests").
			Section(sectionAdminAPI).
			Placeholder("DURATION").
			Validate(tinyflags.Positive[time.Duration]()).
			Value(),
		MaintenanceTimeout: cmd.Duration("maintenance-timeout", client.DefaultMaintenanceTimeout, "Timeout for administrative maintenance HTTP requests").
			Section(sectionAdminAPI).
			Placeholder("DURATION").
			Validate(tinyflags.Positive[time.Duration]()).
			Value(),
		MaxResponseBytes: cmd.Int("max-response-bytes", client.DefaultMaxResponseBytes, "Maximum successful administrative response size in bytes").
			Section(sectionAdminAPI).
			Placeholder("BYTES").
			Validate(client.ValidateMaxResponseBytes).
			Value(),
	}

	cmd.Validate(func() error { return validateAdminURL(flags.ApplicationURL, server) })

	return flags
}

// ValidateListenAddress rejects an empty TCP address while allowing explicit IPs with port zero.
func ValidateListenAddress(addr *net.TCPAddr) error {
	if addr == nil || (len(addr.IP) == 0 && addr.Port == 0) {
		return errors.New("listen address must specify an IP or a nonzero port")
	}

	return nil
}

// validateAdminURL derives the local API URL when no explicit override was supplied.
func validateAdminURL(applicationURL *string, server *ServerFlags) error {
	if *applicationURL == "" {
		base := url.URL{
			Scheme: "http",
			Host:   connectAddress(*server.ListenAddress),
			Path:   server.RoutePrefix,
		}

		*applicationURL = base.String()
	}

	return client.ValidateURL(*applicationURL)
}

// connectAddress substitutes a reachable loopback address for a wildcard bind.
func connectAddress(addr net.TCPAddr) string {
	switch {
	case len(addr.IP) == 0 || addr.IP.Equal(net.IPv4zero):
		addr.IP = net.IPv4(127, 0, 0, 1)
		addr.Zone = ""
	case addr.IP.Equal(net.IPv6zero):
		addr.IP = net.IPv6loopback
		addr.Zone = ""
	}

	return addr.String()
}
