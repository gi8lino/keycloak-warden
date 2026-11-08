// Package bootstrap constructs configured infrastructure and provider instances.
package bootstrap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/containeroo/resolver"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/providers/cloudflare"
	"github.com/gi8lino/keycloak-warden/internal/providers/webhook"
	"github.com/gi8lino/keycloak-warden/internal/urlpolicy"
)

var defaultClientTimeout = 5 * time.Second

// Destinations constructs the enabled providers and returns their stable routing order.
func Destinations(targets map[string]config.Target) (providers map[string]actions.Provider, names []string, err error) {
	providers = make(map[string]actions.Provider)
	client := &http.Client{
		Timeout:       defaultClientTimeout,
		CheckRedirect: noRedirect,
	}
	// Reject missing, empty and misspelled secret references before starting.
	secrets := resolver.NewDefaultRegistry(
		resolver.WithEmptyValuePolicy(resolver.RejectBlank),
		resolver.WithUnknownSchemePolicy(resolver.ErrorOnUnknown),
	)
	// Kubernetes Secret volumes commonly end in a newline. Keep meaningful spaces.
	secrets.Register("file:", &resolver.KeyValueFileResolver{
		Whitespace: resolver.FileTrimNewlines,
	})

	for name, target := range targets {
		if strings.TrimSpace(name) == "" {
			return nil, nil, errors.New("target name is required")
		}

		if !target.Enabled {
			continue
		}

		p, err := build(target, client, secrets)
		if err != nil {
			return nil, nil, fmt.Errorf("target %q: %w", name, err)
		}

		providers[name] = p
	}

	return providers, slices.Sorted(maps.Keys(providers)), nil
}

// noRedirect prevents credentials and signed bodies from being forwarded to another endpoint.
func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// validZoneID checks Cloudflare's canonical 16-byte hexadecimal zone identifier.
func validZoneID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// build binds a supported provider to its credentials and immutable target.
func build(d config.Target, client *http.Client, secrets *resolver.Registry) (actions.Provider, error) {
	secret, err := secrets.ResolveVariable(d.Secret)
	if err != nil {
		return nil, fmt.Errorf("resolve destination credential: %w", err)
	}

	switch d.Provider {
	case config.ProviderWebhook:
		u, err := url.Parse(d.URL)
		if err != nil || !allowedWebhook(u) {
			return nil, errors.New("expected HTTPS webhook URL (HTTP allowed on loopback)")
		}
		return webhook.Provider{
			URL:    d.URL,
			Secret: secret,
			Client: client,
		}, nil

	case config.ProviderCloudflare:
		if !validZoneID(d.ZoneID) {
			return nil, errors.New("expected a 32-digit hexadecimal zone ID")
		}
		endpoint := "https://api.cloudflare.com/client/v4/zones/" + d.ZoneID + "/firewall/access_rules/rules"

		return cloudflare.Provider{
			RulesURL: endpoint,
			Token:    secret,
			Client:   client,
		}, nil

	default:
		return nil, errors.New("unknown provider")
	}
}

// allowedWebhook checks webhook-specific URL restrictions and the shared transport policy.
func allowedWebhook(u *url.URL) bool {
	return u != nil &&
		u.Hostname() != "" &&
		u.User == nil &&
		u.Fragment == "" &&
		urlpolicy.AllowedTransport(u)
}
