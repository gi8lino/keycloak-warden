// Package config defines Warden's detection and destination configuration.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

// Enforcements groups named desired-state destinations by provider.
type Enforcements struct {
	// Delivery contains the shared webhook and retry settings.
	Delivery `yaml:",inline"`
	// Cloudflare maps names to Cloudflare zones.
	Cloudflare map[string]CloudflareTarget `yaml:"cloudflare"`
}

// WebhookTarget configures an outbound HTTP destination.
type WebhookTarget struct {
	// MaxAttempts limits delivery attempts per revision or incident; omission inherits the default.
	MaxAttempts *int `yaml:"max-attempts"`
	// URL is the resolvable outbound webhook endpoint.
	URL string `yaml:"url"`
	// Headers maps literal HTTP header names to resolvable values.
	Headers map[string]string `yaml:"headers"`
	// BodyTemplate optionally resolves to a Go text/template for the JSON request body.
	// When unset, the destination uses its default payload format.
	BodyTemplate string `yaml:"body-template"`
	// TemplateVars maps template-visible names to destination-specific resolver values.
	TemplateVars map[string]string `yaml:"template-vars"`
	// Response optionally overrides accepted HTTP statuses and validates response bodies.
	// A nil response accepts HTTP 2xx.
	Response *WebhookResponse `yaml:"response"`
}

// CloudflareTarget configures one Cloudflare zone destination.
type CloudflareTarget struct {
	// MaxAttempts limits delivery attempts per revision; omission inherits the default.
	MaxAttempts *int `yaml:"max-attempts"`
	// APIToken authorizes Cloudflare API requests and supports resolver references.
	APIToken string `yaml:"api-token"`
	// ZoneID identifies the Cloudflare zone and supports resolver references.
	ZoneID string `yaml:"zone-id"`
}

// Config contains detection and action destination configuration from YAML.
type Config struct {
	// ProtectedIPs lists addresses and CIDRs exempt from bans.
	ProtectedIPs []string `yaml:"protected-ips"`
	// Rules configures named detection rules.
	Rules detection.Rules `yaml:"rules"`
	// IncidentRetention controls how long incident history is kept; zero uses 30 days.
	IncidentRetention time.Duration `yaml:"incident-retention"`
	// Enforcements groups named destinations by provider.
	Enforcements Enforcements `yaml:"enforcements"`
	// Notifications groups incident destinations and their retry settings.
	Notifications Notifications `yaml:"notifications"`
}

// Validate checks the detection rules, protected addresses and structural target configuration.
func (cfg Config) Validate() error {
	if cfg.IncidentRetention != 0 && (cfg.IncidentRetention < 24*time.Hour || cfg.IncidentRetention > 365*24*time.Hour) {
		return errors.New("incident-retention must be between 24h and 8760h")
	}
	if err := cfg.Rules.Validate(); err != nil {
		return fmt.Errorf("detection rules: %w", err)
	}
	if _, err := bans.NewProtection(cfg.ProtectedIPs); err != nil {
		return err
	}
	if err := cfg.Enforcements.Validate(); err != nil {
		return err
	}
	return cfg.Notifications.Validate(cfg.Rules)
}

// ObservationWindow returns the longest configured counting window.
func (cfg Config) ObservationWindow() time.Duration {
	var window time.Duration
	for _, rule := range cfg.Rules {
		window = max(window, rule.Aggregation.Window)
	}
	return window
}

// IncidentHistoryRetention returns the effective incident retention duration.
func (cfg Config) IncidentHistoryRetention() time.Duration {
	if cfg.IncidentRetention == 0 {
		return 30 * 24 * time.Hour
	}
	return cfg.IncidentRetention
}
