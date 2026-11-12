package client

import (
	"context"
	"net/http"
)

// MaintenanceStatus reads the in-process housekeeping status from the application API.
func (c *Client) MaintenanceStatus(ctx context.Context) (Maintenance, error) {
	return c.doMaintenanceRequest(ctx, http.MethodGet, "/maintenance")
}

// PruneObservations requests cleanup of expired login failure observations.
func (c *Client) PruneObservations(ctx context.Context) (Maintenance, error) {
	return c.doMaintenanceRequest(ctx, http.MethodPost, "/maintenance/prune")
}

// OptimizeDatabase requests a SQLite query planner statistics refresh.
func (c *Client) OptimizeDatabase(ctx context.Context) (Maintenance, error) {
	return c.doMaintenanceRequest(ctx, http.MethodPost, "/maintenance/optimize")
}

// doMaintenanceRequest executes an operation and decodes the resulting scheduler state.
func (c *Client) doMaintenanceRequest(ctx context.Context, method, path string) (Maintenance, error) {
	var result Maintenance
	if err := c.doWithTimeout(ctx, method, path, nil, &result, maintenanceClientTimeout); err != nil {
		return Maintenance{}, err
	}
	return result, nil
}
