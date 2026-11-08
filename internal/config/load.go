// Package config loads the strict YAML rules and destination configuration.
package config

import (
	"errors"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

// document represents only detection and destination settings; operational settings are CLI flags.
type document struct {
	// Rule contains the failed-login detection settings.
	Rule struct {
		// Threshold is the number of distinct failures required to trigger detection.
		Threshold int `yaml:"threshold"`
		// Window is the sliding counting window in Go duration syntax.
		Window string `yaml:"window"`
		// Ban is the automatic block lifetime in Go duration syntax.
		Ban string `yaml:"ban"`
	} `yaml:"rule"`
	// Targets maps stable destination names to their configuration.
	Targets map[string]struct {
		// Enabled selects this target for decision delivery.
		Enabled bool `yaml:"enabled"`
		// Provider names the destination implementation.
		Provider string `yaml:"provider"`
		// URL is the configured webhook endpoint.
		URL string `yaml:"url"`
		// Secret signs webhook messages or authorizes provider API calls.
		Secret string `yaml:"secret"`
		// ZoneID selects the Cloudflare zone.
		ZoneID string `yaml:"zone-id"`
	} `yaml:"targets"`
}

// Load reads one strict YAML document containing detection rules and action destinations.
func Load(path string) (cfg Config, err error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close() // nolint:errcheck

	var raw document
	loader, err := yaml.NewLoader(file, yaml.WithKnownFields(), yaml.WithUniqueKeys())
	if err != nil {
		return Config{}, errors.New("invalid Warden YAML: cannot initialize loader")
	}
	if err := loader.Load(&raw); err != nil {
		return Config{}, errors.New("invalid Warden YAML: check field names, types and duplicates")
	}

	if err := loader.Load(new(any)); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("expected one YAML document")
	}

	window, err := duration(raw.Rule.Window)
	if err != nil {
		return Config{}, errors.New("invalid Warden YAML: rule.window must be a duration")
	}

	ban, err := duration(raw.Rule.Ban)
	if err != nil {
		return Config{}, errors.New("invalid Warden YAML: rule.ban must be a duration")
	}

	cfg = Config{
		Rule:    detection.Rule{Threshold: raw.Rule.Threshold, Window: window, Ban: ban},
		Targets: make(map[string]Target, len(raw.Targets)),
	}

	for name, target := range raw.Targets {
		provider := ProviderKind(target.Provider)
		if target.Provider != "" && !provider.Valid() {
			return Config{}, errors.New("invalid Warden YAML: unsupported target provider")
		}
		cfg.Targets[name] = Target{
			Enabled:  target.Enabled,
			Provider: provider,
			URL:      target.URL,
			Secret:   target.Secret,
			ZoneID:   target.ZoneID,
		}
	}
	return cfg, nil
}

// duration parses an optional duration; missing values remain zero for rule validation.
func duration(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}
