// Package bootstrap constructs configured infrastructure and provider instances.
package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/containeroo/notifykit/response"
	"github.com/containeroo/notifykit/templates"
	"github.com/containeroo/resolver"
	"golang.org/x/net/http/httpguts"

	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/providers/cloudflare"
	"github.com/gi8lino/keycloak-warden/internal/providers/webhook"
	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/internal/urlpolicy"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// defaultClientTimeout limits the duration of outbound provider HTTP requests.
const defaultClientTimeout = 5 * time.Second

// Destinations constructs each named provider and returns stable provider-qualified names.
func Destinations(targets config.Enforcements) (destinations map[string]enforcement.Target, names []string, err error) {
	if err := targets.Validate(); err != nil {
		return nil, nil, err
	}

	destinations = make(map[string]enforcement.Target, len(targets.Webhook)+len(targets.Cloudflare))
	defaultLimit := effectiveMaxAttempts(targets.MaxAttempts, retry.DefaultMaxAttempts)

	client, registry := providerDependencies()

	for _, name := range slices.Sorted(maps.Keys(targets.Webhook)) {
		provider, err := buildWebhook(targets.Webhook[name], client, registry, decisionSamples()...)
		if err != nil {
			return nil, nil, fmt.Errorf("target %q: %w", "webhook."+name, err)
		}
		destinations["webhook."+name] = enforcement.Target{
			Provider:    provider,
			Identity:    webhookIdentity(provider),
			MaxAttempts: effectiveMaxAttempts(targets.Webhook[name].MaxAttempts, defaultLimit),
		}
	}

	for _, name := range slices.Sorted(maps.Keys(targets.Cloudflare)) {
		provider, err := buildCloudflare(targets.Cloudflare[name], client, registry)
		if err != nil {
			return nil, nil, fmt.Errorf("target %q: %w", "cloudflare."+name, err)
		}
		destinations["cloudflare."+name] = enforcement.Target{
			Provider:    provider,
			Identity:    fingerprint(provider.RulesURL),
			MaxAttempts: effectiveMaxAttempts(targets.Cloudflare[name].MaxAttempts, defaultLimit),
		}
	}

	return destinations, slices.Sorted(maps.Keys(destinations)), nil
}

// providerDependencies constructs the common bounded transport and value resolver.
func providerDependencies() (*http.Client, *resolver.Registry) {
	client := &http.Client{
		Timeout:       defaultClientTimeout,
		CheckRedirect: noRedirect,
	}

	registry := resolver.NewDefaultRegistry(
		resolver.WithEmptyValuePolicy(resolver.RejectBlank),
		resolver.WithUnknownSchemePolicy(resolver.ErrorOnUnknown),
	)

	return client, registry
}

// effectiveMaxAttempts resolves a per-target override against its inherited limit.
func effectiveMaxAttempts(override *int, fallback int) int {
	if override != nil {
		return *override
	}
	return fallback
}

// noRedirect prevents credentials from being forwarded to another endpoint.
func noRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// decisionSamples covers both desired states during template validation.
func decisionSamples() []model.Decision {
	return []model.Decision{
		{
			ID:        "startup-check",
			Revision:  1,
			IP:        "203.0.113.1",
			State:     model.DecisionBanned,
			ExpiresAt: time.Unix(0, 0).UTC(),
		},
		{
			ID:       "startup-check",
			Revision: 2,
			IP:       "203.0.113.1",
			State:    model.DecisionUnbanned,
		},
	}
}

// buildWebhook resolves shared endpoint settings and validates representative payloads.
func buildWebhook[T any](target config.WebhookTarget, client *http.Client, registry *resolver.Registry, samples ...T) (webhook.Provider[T], error) {
	endpoint, err := resolveWebhookURL(registry, target.URL)
	if err != nil {
		return webhook.Provider[T]{}, err
	}

	headers, err := resolveWebhookHeaders(registry, target.Headers)
	if err != nil {
		return webhook.Provider[T]{}, err
	}

	bodyTemplate, err := parseWebhookBodyTemplate(registry, target.BodyTemplate)
	if err != nil {
		return webhook.Provider[T]{}, err
	}

	vars, err := resolveTemplateVars(registry, target.TemplateVars)
	if err != nil {
		return webhook.Provider[T]{}, err
	}

	var responseRule *response.Rule
	if target.Response != nil {
		rule, err := target.Response.Rule()
		if err != nil {
			return webhook.Provider[T]{}, fmt.Errorf("response: %w", err)
		}
		responseRule = &rule
	}

	provider := webhook.Provider[T]{
		Target:       webhook.NewTarget(endpoint, headers, client, responseRule),
		Template:     bodyTemplate,
		TemplateVars: vars,
	}
	if err := provider.ValidatePayloads(samples...); err != nil {
		return webhook.Provider[T]{}, fmt.Errorf("body-template: %w", err)
	}
	return provider, nil
}

// resolveTemplateVars resolves only the variables explicitly configured for this destination.
func resolveTemplateVars(registry *resolver.Registry, configured map[string]string) (map[string]string, error) {
	vars := make(map[string]string, len(configured))
	for _, name := range slices.Sorted(maps.Keys(configured)) {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("template-vars: variable name must not be blank")
		}
		value, err := registry.ResolveVariable(configured[name])
		if err != nil {
			return nil, fmt.Errorf("template-vars %q: %w", name, err)
		}
		vars[name] = value
	}

	return vars, nil
}

// resolveWebhookURL resolves and validates a webhook endpoint.
// Literal HTTP(S) URLs are supported alongside resolver references.
func resolveWebhookURL(
	registry *resolver.Registry,
	reference string,
) (string, error) {
	if strings.HasPrefix(reference, "https://") || strings.HasPrefix(reference, "http://") {
		// HTTP(S) URL schemes are not resolver schemes; treat them as literals.
		reference = "literal:" + reference
	}

	endpoint, err := registry.ResolveVariable(reference)
	if err != nil {
		return "", fmt.Errorf("url: %w", err)
	}

	u, err := url.Parse(endpoint)
	if err != nil || !allowedWebhook(u) {
		return "", errors.New("url: expected HTTPS webhook URL (HTTP allowed on loopback)")
	}

	return endpoint, nil
}

// allowedWebhook checks webhook-specific URL restrictions and the shared transport policy.
func allowedWebhook(u *url.URL) bool {
	return u != nil &&
		u.Hostname() != "" &&
		u.User == nil &&
		u.Fragment == "" &&
		urlpolicy.AllowedTransport(u)
}

// resolveWebhookHeaders resolves and validates configured HTTP headers.
func resolveWebhookHeaders(
	registry *resolver.Registry,
	configuredHeaders map[string]string,
) (map[string]string, error) {
	headers := make(map[string]string, len(configuredHeaders))

	for _, name := range slices.Sorted(maps.Keys(configuredHeaders)) {
		value, err := registry.ResolveVariable(configuredHeaders[name])
		if err != nil {
			return nil, fmt.Errorf("headers %s: %w", name, err)
		}

		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("headers %q: invalid HTTP header value", name)
		}

		headers[http.CanonicalHeaderKey(name)] = value
	}

	return headers, nil
}

// parseWebhookBodyTemplate resolves and parses the configured body template.
func parseWebhookBodyTemplate(
	registry *resolver.Registry,
	reference string,
) (*templates.Template, error) {
	if reference == "" {
		return nil, nil
	}

	source, err := registry.ResolveVariable(reference)
	if err != nil {
		return nil, fmt.Errorf("body-template: %w", err)
	}

	bodyTemplate, err := templates.ParseTemplate(
		"webhook-body",
		source,
		templates.WithDefaultFuncs(),
	)
	if err != nil {
		return nil, fmt.Errorf("body-template: %w", err)
	}

	return bodyTemplate, nil
}

// buildCloudflare resolves zone configuration once before constructing a provider.
func buildCloudflare(
	target config.CloudflareTarget,
	client *http.Client,
	registry *resolver.Registry,
) (cloudflare.Provider, error) {
	zoneID, err := registry.ResolveVariable(target.ZoneID)
	if err != nil {
		return cloudflare.Provider{}, fmt.Errorf("zone-id: %w", err)
	}

	if !validZoneID(zoneID) {
		return cloudflare.Provider{}, errors.New("zone-id: expected a 32-character hexadecimal Cloudflare zone ID")
	}

	token, err := registry.ResolveVariable(target.APIToken)
	if err != nil {
		return cloudflare.Provider{}, fmt.Errorf("api-token: %w", err)
	}

	return cloudflare.Provider{
		RulesURL: "https://api.cloudflare.com/client/v4/zones/" + strings.ToLower(zoneID) + "/firewall/access_rules/rules",
		Token:    token,
		Client:   client,
	}, nil
}

// validZoneID checks Cloudflare's canonical 16-byte hexadecimal zone identifier.
func validZoneID(value string) bool {
	if len(value) != 32 {
		return false
	}

	_, err := hex.DecodeString(value)
	return err == nil
}

// fingerprint avoids persisting secret-bearing webhook URLs.
func fingerprint(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:])
}

// webhookIdentity includes routing variables as well as the endpoint; credentials stay rotatable.
func webhookIdentity[T any](provider webhook.Provider[T]) string {
	// Encoding a map of strings is deterministic and cannot fail.
	encoded, _ := json.Marshal(provider.TemplateVars)
	return fingerprint(provider.Target.URL + "\x00" + string(encoded))
}
