// Package config defines Warden's detection and destination configuration.
package config

import "github.com/gi8lino/keycloak-warden/internal/application/detection"

// Targets groups named destinations by their provider type.
type Targets struct {
	// Webhook maps names to outbound HTTP webhook destinations.
	Webhook map[string]WebhookTarget `yaml:"webhook"`
	// Cloudflare maps names to Cloudflare zones.
	Cloudflare map[string]CloudflareTarget `yaml:"cloudflare"`
}

// WebhookTarget configures an HTTP notification destination.
type WebhookTarget struct {
	// URL is the resolvable outbound webhook endpoint.
	URL string `yaml:"url"`
	// Headers maps literal HTTP header names to resolvable values.
	Headers map[string]string `yaml:"headers"`
}

// CloudflareTarget configures one Cloudflare zone destination.
type CloudflareTarget struct {
	// APIToken authorizes Cloudflare API requests and supports resolver references.
	APIToken string `yaml:"api-token"`
	// ZoneID identifies the Cloudflare zone and supports resolver references.
	ZoneID string `yaml:"zone-id"`
}

// Config contains detection and action destination configuration from YAML.
type Config struct {
	// Rule configures the failed-login detector.
	Rule detection.Rule
	// Targets groups named destinations by provider.
	Targets Targets
}

// Validate checks the detection rule and structural target configuration.
func (cfg Config) Validate() error {
	if err := cfg.Rule.Validate(); err != nil {
		return err
	}
	if err := cfg.Targets.Validate(); err != nil {
		return err
	}
	return nil
}
