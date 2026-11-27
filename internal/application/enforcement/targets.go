package enforcement

import (
	"context"
	"fmt"
	"slices"
)

// ManagedTargetReader reports destinations still referenced by durable decisions.
type ManagedTargetReader interface {
	// ManagedTargets returns persisted destination names that must not be abandoned.
	ManagedTargets(context.Context) ([]string, error)
}

// ValidateTargets refuses to abandon a ban or an unacknowledged release when
// reloading destination configuration. It runs before delivery workers start.
func ValidateTargets(ctx context.Context, store ManagedTargetReader, configured []string) error {
	managed, err := store.ManagedTargets(ctx)
	if err != nil {
		return err
	}

	for _, name := range managed {
		if !slices.Contains(configured, name) {
			return fmt.Errorf("destination %q has managed decisions; keep it configured until release", name)
		}
	}

	return nil
}
