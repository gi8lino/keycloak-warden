package config

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode"
)

// Validate checks target names, required fields and webhook header names.
func (targets Targets) Validate() error {
	if len(targets.Webhook)+len(targets.Cloudflare) == 0 {
		return errors.New("at least one webhook or cloudflare target is required")
	}

	// Sort names so the same configuration always reports the same first error.
	for _, name := range slices.Sorted(maps.Keys(targets.Webhook)) {
		if err := validateWebhookTarget(name, targets.Webhook[name]); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(targets.Cloudflare)) {
		if err := validateCloudflareTarget(name, targets.Cloudflare[name]); err != nil {
			return err
		}
	}
	return nil
}

// validateWebhookTarget checks a named webhook's endpoint and uniquely named headers.
func validateWebhookTarget(name string, target WebhookTarget) error {
	id := "webhook." + name
	if err := validateTargetName(name); err != nil {
		return fmt.Errorf("target %q: %w", id, err)
	}
	if strings.TrimSpace(target.URL) == "" {
		return fmt.Errorf("target %q: url: value must not be blank", id)
	}

	seen := make(map[string]struct{}, len(target.Headers))
	for _, header := range slices.Sorted(maps.Keys(target.Headers)) {
		if err := validateHeaderName(header); err != nil {
			return fmt.Errorf("target %q: headers %q: %w", id, header, err)
		}

		canonical := http.CanonicalHeaderKey(header)
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("target %q: headers %q: duplicate header name", id, header)
		}
		seen[canonical] = struct{}{}

		if strings.TrimSpace(target.Headers[header]) == "" {
			return fmt.Errorf("target %q: headers %s: value must not be blank", id, header)
		}
	}
	return nil
}

// validateCloudflareTarget checks a named zone's resolvable credentials.
func validateCloudflareTarget(name string, target CloudflareTarget) error {
	id := "cloudflare." + name
	if err := validateTargetName(name); err != nil {
		return fmt.Errorf("target %q: %w", id, err)
	}
	if strings.TrimSpace(target.ZoneID) == "" {
		return fmt.Errorf("target %q: zone-id: value must not be blank", id)
	}
	if strings.TrimSpace(target.APIToken) == "" {
		return fmt.Errorf("target %q: api-token: value must not be blank", id)
	}
	return nil
}

// validateTargetName rejects empty names, whitespace and control characters.
func validateTargetName(name string) error {
	if name == "" {
		return errors.New("name must not be empty")
	}

	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("name must not contain whitespace or control characters")
		}
	}
	return nil
}

// validateHeaderName accepts HTTP token names except Warden's JSON Content-Type.
func validateHeaderName(name string) error {
	if name == "" {
		return errors.New("header name must not be empty")
	}

	for i := range len(name) {
		if !isTokenChar(name[i]) {
			return errors.New("invalid HTTP header name")
		}
	}

	if strings.EqualFold(name, "Content-Type") {
		return errors.New("Content-Type is reserved for application/json")
	}

	return nil
}

// isTokenChar implements RFC 9110 HTTP field-name token characters.
func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}
