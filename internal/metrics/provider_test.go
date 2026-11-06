package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// providerStub supplies a deterministic successful or failed action result.
type providerStub struct {
	// err is the failure returned by the test provider.
	err error
}

// Apply returns the configured delivery outcome.
func (p providerStub) Apply(context.Context, decisions.Decision) error { return p.err }

func TestInstrumentProvider(t *testing.T) {
	t.Parallel()

	t.Run("records successful destination attempts", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		wrapped := registry.InstrumentProvider("edge", providerStub{})
		require.NoError(t, wrapped.Apply(t.Context(), decisions.Decision{}))

		output := scrape(t, registry)
		assert.Contains(t, output, `warden_delivery_attempts_total{destination="edge",outcome="success"} 1`)
		assert.Contains(t, output, `warden_delivery_duration_seconds_count{destination="edge"} 1`)
	})

	t.Run("records failed destination attempts", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		wrapped := registry.InstrumentProvider("ops", providerStub{err: errors.New("failed")})
		require.Error(t, wrapped.Apply(t.Context(), decisions.Decision{}))

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
