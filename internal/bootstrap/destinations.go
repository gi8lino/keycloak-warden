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

// Destinations constructs each named provider and returns stable provider-qualified names.
func Destinations(targets config.Targets) (providers map[string]actions.Provider, names []string, err error) {
	if err := targets.Validate(); err != nil {
		return nil, nil, err
	}

	providers = make(map[string]actions.Provider, len(targets.Webhook)+len(targets.Cloudflare))

	client := &http.Client{
		Timeout:       defaultClientTimeout,
		CheckRedirect: noRedirect,
	}

	values := resolver.NewDefaultRegistry(
		resolver.WithEmptyValuePolicy(resolver.RejectBlank),
		resolver.WithUnknownSchemePolicy(resolver.ErrorOnUnknown),
	)
	// Kubernetes Secret volumes commonly end in a newline. Keep meaningful spaces.
	values.Register("file:", &resolver.KeyValueFileResolver{Whitespace: resolver.FileTrimNewlines})

	for name, target := range targets.Webhook {
		provider, err := buildWebhook(target, client, values)
		if err != nil {
			return nil, nil, fmt.Errorf("target %q: %w", "webhook."+name, err)
		}
		providers["webhook."+name] = provider
	}

	for name, target := range targets.Cloudflare {
		provider, err := buildCloudflare(target, client, values)
		if err != nil {
			return nil, nil, fmt.Errorf("target %q: %w", "cloudflare."+name, err)
		}
		providers["cloudflare."+name] = provider
	}

	return providers, slices.Sorted(maps.Keys(providers)), nil
}

// noRedirect prevents credentials from being forwarded to another endpoint.
func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// validZoneID checks Cloudflare's canonical 16-byte hexadecimal zone identifier.
func validZoneID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// buildWebhook resolves all endpoint settings once before constructing a provider.
func buildWebhook(
	target config.WebhookTarget,
	client *http.Client,
	values *resolver.Registry,
) (actions.Provider, error) {
	endpoint, err := resolveWebhookURL(values, target.URL)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(endpoint)
	if err != nil || !allowedWebhook(u) {
		return nil, errors.New("url: expected HTTPS webhook URL (HTTP allowed on loopback)")
	}

	headers := make(http.Header, len(target.Headers))
	for name, reference := range target.Headers {
		canonical := http.CanonicalHeaderKey(name)
		value, err := resolveRequired(values, reference, "headers "+name)
		if err != nil {
			return nil, err
		}
		if !validHeaderValue(value) {
			return nil, fmt.Errorf("headers %q: invalid HTTP header value", name)
		}
		headers.Set(canonical, value)
	}

	return webhook.Provider{
		URL:     endpoint,
		Headers: headers,
		Client:  client,
	}, nil
}

// buildCloudflare resolves zone configuration once before constructing a provider.
func buildCloudflare(
	target config.CloudflareTarget,
	client *http.Client,
	values *resolver.Registry,
) (actions.Provider, error) {
	zoneID, err := resolveRequired(values, target.ZoneID, "zone-id")
	if err != nil {
		return nil, err
	}

	if !validZoneID(zoneID) {
		return nil, errors.New("zone-id: expected a 32-character hexadecimal Cloudflare zone ID")
	}

	token, err := resolveRequired(values, target.APIToken, "api-token")
	if err != nil {
		return nil, err
	}

	return cloudflare.Provider{
		RulesURL: "https://api.cloudflare.com/client/v4/zones/" + zoneID + "/firewall/access_rules/rules",
		Token:    token,
		Client:   client,
	}, nil
}

// resolveWebhookURL accepts literal HTTP(S) URLs and resolver references.
func resolveWebhookURL(values *resolver.Registry, reference string) (string, error) {
	if strings.HasPrefix(reference, "https://") || strings.HasPrefix(reference, "http://") {
		// HTTP(S) URL schemes are not resolver schemes; treat them as literals.
		reference = "literal:" + reference
	}
	return resolveRequired(values, reference, "url")
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

// validHeaderValue rejects control characters, including CR and LF injection.
func validHeaderValue(value string) bool {
	for i := range len(value) {
		if value[i] < ' ' && value[i] != '\t' || value[i] == 0x7f {
			return false
		}
	}
	return true
}

// allowedWebhook checks webhook-specific URL restrictions and the shared transport policy.
func allowedWebhook(u *url.URL) bool {
	return u != nil &&
		u.Hostname() != "" &&
		u.User == nil &&
		u.Fragment == "" &&
		urlpolicy.AllowedTransport(u)
}
