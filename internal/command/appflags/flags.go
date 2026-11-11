// Package appflags defines application endpoint flags shared by Warden subcommands.
package appflags

import (
	"fmt"
	"net"
	"net/url"

	"github.com/containeroo/httpkit/prefix"
	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/keycloak-warden/internal/adminclient"
)

// Flags holds the global application listener settings parsed by tinyflags.
type Flags struct {
	// ListenAddress identifies the application interface and port.
	ListenAddress *string
	// RoutePrefix is the normalized base path of the application API.
	RoutePrefix *string
}

// Register registers the shared application endpoint on the root command.
func Register(root *tinyflags.Command) Flags {
	return Flags{
		ListenAddress: root.Globals().String("listen-address", "127.0.0.1:8080", "Application listener address").
			NotBlank().
			Placeholder("ADDR").
			Value(),
		RoutePrefix: root.Globals().String("route-prefix", "", "Application API route prefix").
			Validate(prefix.ValidateRoutePrefix).
			Finalize(prefix.NormalizeRoutePrefix).
			Value(),
	}
}

// ApplicationURLFlag finalizes the client URL after tinyflags parses the root and command flags.
func (f Flags) ApplicationURLFlag(cmd *tinyflags.Command) *string {
	address := cmd.String("application-url", "", "Override the URL derived from --listen-address and --route-prefix").
		Value()
	cmd.Validate(func() error {
		if *address == "" {
			host, port, err := net.SplitHostPort(*f.ListenAddress)
			if err != nil {
				return fmt.Errorf("invalid --listen-address: %w", err)
			}
			base := url.URL{
				Scheme: "http",
				Host:   net.JoinHostPort(connectHost(host), port),
				Path:   *f.RoutePrefix,
			}
			*address = base.String()
		}
		return adminclient.ValidateURL(*address)
	})
	return address
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

// AdminTokenFlag registers a protected application API credential on an administrative command.
func AdminTokenFlag(cmd *tinyflags.Command) *string {
	return cmd.String("admin-token", "", "Application API administrator bearer token").
		Placeholder("SECRET").
		OverriddenValueMaskFn(tinyflags.MaskFirstLastLimit(5)).
		Value()
}
