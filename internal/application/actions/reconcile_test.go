package actions

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingReconciler records destination limits supplied during startup.
type recordingReconciler struct {
	// calls lists the destinations and budgets passed to persistence.
	calls []reconcileCall
	// failOn selects the destination whose reconciliation fails.
	failOn string
}

// reconcileCall describes one destination's startup synchronization.
type reconcileCall struct {
	// name identifies the configured target.
	name string
	// limit is the resolved maximum number of delivery attempts.
	limit int
}

// ReconcileAttemptLimit records the request and optionally returns a failure.
func (r *recordingReconciler) ReconcileAttemptLimit(_ context.Context, name string, limit int) error {
	r.calls = append(r.calls, reconcileCall{name: name, limit: limit})
	if name == r.failOn {
		return errors.New("database unavailable")
	}
	return nil
}

func TestReconcileTargets(t *testing.T) {
	t.Parallel()

	t.Run("passes each target limit in stable order", func(t *testing.T) {
		t.Parallel()

		store := &recordingReconciler{}
		targets := map[string]Target{
			"webhook.slack":   {MaxAttempts: 5},
			"cloudflare.edge": {MaxAttempts: 2},
		}

		err := ReconcileTargets(t.Context(), store, targets)

		require.NoError(t, err)
		assert.Equal(t, []reconcileCall{
			{name: "cloudflare.edge", limit: 2},
			{name: "webhook.slack", limit: 5},
		}, store.calls)
	})

	t.Run("accepts empty targets", func(t *testing.T) {
		t.Parallel()

		store := &recordingReconciler{}

		err := ReconcileTargets(t.Context(), store, nil)

		require.NoError(t, err)
		assert.Empty(t, store.calls)
	})

	t.Run("returns the destination on a reconciliation failure", func(t *testing.T) {
		t.Parallel()

		store := &recordingReconciler{failOn: "webhook.slack"}
		targets := map[string]Target{
			"cloudflare.edge": {MaxAttempts: 2},
			"webhook.slack":   {MaxAttempts: 5},
			"webhook.teams":   {MaxAttempts: 3},
		}

		err := ReconcileTargets(t.Context(), store, targets)

		require.ErrorContains(t, err, `target "webhook.slack": database unavailable`)
		assert.Equal(t, []reconcileCall{
			{name: "cloudflare.edge", limit: 2},
			{name: "webhook.slack", limit: 5},
		}, store.calls)
	})
}
