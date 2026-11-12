// Package maintenance exposes Warden's authenticated database housekeeping API through the CLI.
package maintenance

import (
	"context"
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Action identifies a supported remote maintenance command.
type Action string

const (
	// ActionStatus reports the most recent maintenance outcomes.
	ActionStatus Action = "status"
	// ActionPrune removes expired failure observations without touching decisions.
	ActionPrune Action = "prune"
	// ActionOptimize refreshes SQLite's query planner statistics.
	ActionOptimize Action = "optimize"
)

// Run calls the authenticated application API and encodes the returned status.
func Run(ctx context.Context, applicationURL, token string, action Action, encode output.Encoder) error {
	api, err := client.New(applicationURL, token)
	if err != nil {
		return err
	}

	var status client.Maintenance
	switch action {
	case ActionStatus:
		status, err = api.MaintenanceStatus(ctx)
	case ActionPrune:
		status, err = api.PruneObservations(ctx)
	case ActionOptimize:
		status, err = api.OptimizeDatabase(ctx)
	default:
		return fmt.Errorf("unsupported maintenance action %q", action)
	}

	if err != nil {
		return err
	}

	return encode(status)
}
