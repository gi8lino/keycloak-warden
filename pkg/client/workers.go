package client

import (
	"context"
	"net/http"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// WorkerStatus retrieves the worker status report.
func (c *Client) WorkerStatus(ctx context.Context) (model.Workers, error) {
	var result model.Workers
	if err := c.do(ctx, http.MethodGet, "/workers", nil, &result); err != nil {
		return model.Workers{}, err
	}
	return result, nil
}
