package enforcement

import (
	"context"
	"fmt"
	"maps"
	"slices"
)

// AttemptLimitReconciler synchronizes persisted delivery states with one target's budget.
type AttemptLimitReconciler interface {
	// ReconcileAttemptLimit updates the current deliveries of a named destination.
	ReconcileAttemptLimit(context.Context, string, AttemptLimit) error
}

// ReconcileTargets applies the configured targets' attempt budgets before the worker starts.
func ReconcileTargets(ctx context.Context, store AttemptLimitReconciler, targets map[string]Target) error {
	for _, name := range slices.Sorted(maps.Keys(targets)) {
		if err := store.ReconcileAttemptLimit(ctx, name, AttemptLimit(targets[name].MaxAttempts)); err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
	}

	return nil
}
