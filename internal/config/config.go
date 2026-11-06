// Package config defines Warden's detection and destination configuration.
package config

import "github.com/gi8lino/keycloak-warden/internal/application/detection"

// Target describes one named action destination.
type Target struct {
	// Enabled selects the destination for detection decisions.
	Enabled bool
	// Provider identifies the destination implementation.
	Provider ProviderKind
	// URL is the outbound webhook endpoint.
	URL string
	// Secret signs outbound webhooks or authenticates Cloudflare requests.
	Secret string
	// ZoneID identifies a Cloudflare zone.
	ZoneID string
}

// Config contains detection and action destination configuration from YAML.
type Config struct {
	// Rule configures the failed-login detector.
	Rule detection.Rule
	// Targets maps stable destination names to their settings.
	Targets map[string]Target
}

// Validate checks the detection rule loaded from YAML.
func (cfg Config) Validate() error {
	return cfg.Rule.Validate()
}
