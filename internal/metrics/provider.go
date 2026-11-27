package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// InstrumentProvider wraps enforcement delivery with success, error, and duration metrics.
func (r *Registry) InstrumentProvider(name string, provider enforcement.Provider) enforcement.Provider {
	return instrumentProvider[model.Decision](r.enabled, name, provider, r.deliveryAttempts, r.deliveryDuration)
}

// InstrumentNotificationProvider wraps incident delivery using independent notification metrics.
func (r *Registry) InstrumentNotificationProvider(name string, provider notifications.Provider) notifications.Provider {
	return instrumentProvider[model.Incident](r.enabled, name, provider, r.notificationAttempts, r.notificationDuration)
}

// deliveryProvider is the transport-neutral delivery contract.
type deliveryProvider[T any] interface {
	Deliver(context.Context, T) error
}

// instrumentProvider attaches the supplied metric collectors to any typed sender.
func instrumentProvider[T any](enabled bool, name string, provider deliveryProvider[T], attempts *prometheus.CounterVec, duration *prometheus.HistogramVec) deliveryProvider[T] {
	if !enabled {
		return provider
	}
	return &instrumentedProvider[T]{
		name:     name,
		provider: provider,
		attempts: attempts,
		duration: duration,
	}
}

// instrumentedProvider records outbound delivery outcomes independently of payload type.
type instrumentedProvider[T any] struct {
	// name identifies the configured destination.
	name string
	// provider performs the underlying delivery operation.
	provider deliveryProvider[T]
	// attempts counts the results of completed outbound calls.
	attempts *prometheus.CounterVec
	// duration measures outbound call latency.
	duration *prometheus.HistogramVec
}

// Deliver delegates the payload and records the outcome of one attempt.
func (p *instrumentedProvider[T]) Deliver(ctx context.Context, payload T) error {
	started := time.Now()
	err := p.provider.Deliver(ctx, payload)
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	p.attempts.WithLabelValues(p.name, outcome).Inc()
	p.duration.WithLabelValues(p.name).Observe(time.Since(started).Seconds())
	return err
}
