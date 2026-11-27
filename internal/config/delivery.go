package config

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/retry"
)

// Delivery contains the common settings for independent delivery workflows.
type Delivery struct {
	// MaxAttempts limits attempts per revision or occurrence; omission uses the default.
	MaxAttempts *int `yaml:"max-attempts"`
	// RetryInitialDelay overrides the initial retry pause.
	RetryInitialDelay time.Duration `yaml:"retry-initial-delay"`
	// RetryMaxDelay overrides the maximum retry pause.
	RetryMaxDelay time.Duration `yaml:"retry-max-delay"`
	// Webhook maps names to outbound HTTP destinations.
	Webhook map[string]WebhookTarget `yaml:"webhook"`
}

// RetryPolicy returns the effective retry settings.
func (d Delivery) RetryPolicy() retry.RetryPolicy {
	policy := retry.DefaultRetryPolicy()
	if d.RetryInitialDelay != 0 {
		policy.InitialDelay = d.RetryInitialDelay
	}
	if d.RetryMaxDelay != 0 {
		policy.MaxDelay = d.RetryMaxDelay
	}
	return policy
}

// validate checks common retry settings and webhook definitions.
func (d Delivery) validate(scope string) error {
	if err := validateMaxAttempts(scope, d.MaxAttempts); err != nil {
		return err
	}
	if err := d.RetryPolicy().Validate(); err != nil {
		return fmt.Errorf("%s: %w", scope, err)
	}
	for _, name := range slices.Sorted(maps.Keys(d.Webhook)) {
		if err := validateWebhookTarget(name, d.Webhook[name]); err != nil {
			return fmt.Errorf("%s: %w", scope, err)
		}
	}
	return nil
}
