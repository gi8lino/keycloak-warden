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

// defaultClientTimeout limits the duration of outbound provider HTTP requests.
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

// build validates and constructs the selected target provider.
func build(d config.Target, client *http.Client, values *resolver.Registry) (actions.Provider, error) {
	switch d.Provider {
	case config.ProviderWebhook:
		u, err := url.Parse(d.URL)
		if err != nil || !allowedWebhook(u) {
			return nil, errors.New("url: expected HTTPS webhook URL (HTTP allowed on loopback)")
		}
		if d.APIToken != "" || d.ZoneID != "" {
			return nil, errors.New("webhook: api-token and zone-id are only valid for Cloudflare targets")
		}
		secret, err := resolveRequired(values, d.SigningSecret, "signing-secret")
		if err != nil {
			return nil, err
		}
		return webhook.Provider{
			URL:    d.URL,
			Secret: secret,
			Client: client,
		}, nil

	case config.ProviderCloudflare:
		if d.URL != "" || d.SigningSecret != "" {
			return nil, errors.New("cloudflare: url and signing-secret are only valid for webhook targets")
		}
		zoneID, err := resolveRequired(values, d.ZoneID, "zone-id")
		if err != nil {
			return nil, err
		}
		if !validZoneID(zoneID) {
			return nil, errors.New("zone-id: expected a 32-character hexadecimal Cloudflare zone ID")
		}
		token, err := resolveRequired(values, d.APIToken, "api-token")
		if err != nil {
			return nil, err
		}
		return cloudflare.Provider{
			RulesURL: "https://api.cloudflare.com/client/v4/zones/" + zoneID + "/firewall/access_rules/rules",
			Token:    token,
			Client:   client,
		}, nil

	default:
		return nil, errors.New("unknown provider")
	}
}

// resolveRequired resolves a provider setting and rejects missing or blank values.
func resolveRequired(values *resolver.Registry, reference, field string) (string, error) {
	value, err := values.ResolveVariable(reference)
	if err != nil {
		return "", fmt.Errorf("%s: resolve value: %w", field, err)
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s: value must not be blank", field)
	}
	return value, nil
}

// allowedWebhook checks webhook-specific URL restrictions and the shared transport policy.
func allowedWebhook(u *url.URL) bool {
	return u != nil &&
		u.Hostname() != "" &&
		u.User == nil &&
		u.Fragment == "" &&
		urlpolicy.AllowedTransport(u)
}
