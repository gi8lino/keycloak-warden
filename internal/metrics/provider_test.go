package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// providerStub supplies a deterministic successful or failed action result.
type providerStub struct {
	// err is the failure returned by the test provider.
	err error
}

// Deliver returns the configured delivery outcome.
func (p providerStub) Deliver(context.Context, model.Decision) error { return p.err }

func TestInstrumentProvider(t *testing.T) {
	t.Parallel()

	t.Run("records successful destination attempts", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		wrapped := registry.InstrumentProvider("edge", providerStub{})
		require.NoError(t, wrapped.Deliver(t.Context(), model.Decision{}))

		output := scrape(t, registry)
		assert.Contains(t, output, `warden_delivery_attempts_total{destination="edge",outcome="success"} 1`)
		assert.Contains(t, output, `warden_delivery_duration_seconds_count{destination="edge"} 1`)
	})

	t.Run("records failed destination attempts", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		wrapped := registry.InstrumentProvider("ops", providerStub{err: errors.New("failed")})
		require.Error(t, wrapped.Deliver(t.Context(), model.Decision{}))

		output := scrape(t, registry)
		assert.Contains(t, output, `warden_delivery_attempts_total{destination="ops",outcome="error"} 1`)
	})

	t.Run("disabled registry preserves original provider", func(t *testing.T) {
		t.Parallel()

		original := providerStub{}
		wrapped := NewRegistry(false, "test").InstrumentProvider("edge", original)
		assert.Equal(t, original, wrapped)
	})
}

// notificationProviderStub returns a configured incident delivery result.
type notificationProviderStub struct {
	// err is the failure returned by the provider.
	err error
}

// Deliver returns the configured outcome.
func (p notificationProviderStub) Deliver(context.Context, model.Incident) error { return p.err }

func TestInstrumentNotificationProvider(t *testing.T) {
	t.Parallel()

	t.Run("records notification metrics separately from enforcement", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		success := registry.InstrumentNotificationProvider("audit", notificationProviderStub{})
		require.NoError(t, success.Deliver(t.Context(), model.Incident{}))
		failure := registry.InstrumentNotificationProvider("audit", notificationProviderStub{err: errors.New("unavailable")})
		require.Error(t, failure.Deliver(t.Context(), model.Incident{}))
		output := scrape(t, registry)
		assert.Contains(t, output, `warden_notification_attempts_total{destination="audit",outcome="success"} 1`)
		assert.Contains(t, output, `warden_notification_attempts_total{destination="audit",outcome="error"} 1`)
		assert.Contains(t, output, `warden_notification_duration_seconds_count{destination="audit"} 2`)
		assert.NotContains(t, output, `warden_delivery_attempts_total{destination="audit"`)
	})

	t.Run("disabled registry returns the original sender", func(t *testing.T) {
		t.Parallel()

		original := notificationProviderStub{}
		assert.Equal(t, original, NewRegistry(false, "test").InstrumentNotificationProvider("audit", original))
	})
}
