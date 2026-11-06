package metrics

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// InstrumentProvider wraps destination delivery with success, error, and duration metrics.
func (r *Registry) InstrumentProvider(name string, provider actions.Provider) actions.Provider {
	if r == nil || !r.enabled {
		return provider
	}
	return &instrumentedProvider{
		registry: r,
		name:     name,
		provider: provider,
	}
}

// instrumentedProvider records delivery outcomes without changing the provider contract.
type instrumentedProvider struct {
	// registry owns the collectors updated by this provider wrapper.
	registry *Registry
	// name identifies the destination in metrics labels.
	name string
	// provider performs the underlying delivery operation.
	provider actions.Provider
}

// Apply delegates the decision and records the outcome of one attempt.
func (p *instrumentedProvider) Apply(ctx context.Context, decision decisions.Decision) error {
	started := time.Now()
	err := p.provider.Apply(ctx, decision)

	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	p.registry.deliveryAttempts.WithLabelValues(p.name, outcome).Inc()
	p.registry.deliveryDuration.WithLabelValues(p.name).Observe(time.Since(started).Seconds())
	return err
}
