package client

import (
	"context"
	"net/http"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// MaintenanceStatus reads the in-process housekeeping status from the application API.
func (c *Client) MaintenanceStatus(ctx context.Context) (model.Maintenance, error) {
	return c.doMaintenanceRequest(ctx, http.MethodGet, "/maintenance")
}

// PruneObservations requests cleanup of expired login failure observations.
func (c *Client) PruneObservations(ctx context.Context) (model.Maintenance, error) {
	return c.doMaintenanceRequest(ctx, http.MethodPost, "/maintenance/prune")
}

// OptimizeDatabase requests a SQLite query planner statistics refresh.
func (c *Client) OptimizeDatabase(ctx context.Context) (model.Maintenance, error) {
	return c.doMaintenanceRequest(ctx, http.MethodPost, "/maintenance/optimize")
}

// doMaintenanceRequest executes an operation and decodes the resulting scheduler state.
func (c *Client) doMaintenanceRequest(ctx context.Context, method, path string) (model.Maintenance, error) {
	var result model.Maintenance
	if err := c.doWithTimeout(ctx, method, path, nil, &result, c.options.maintenanceClientTimeout); err != nil {
		return model.Maintenance{}, err
	}
	return result, nil
}
