package listactive

import (
	"context"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// execute fetches current active bans from the authenticated application API.
func execute(ctx context.Context, api *client.Client) ([]client.Record, error) {
	return api.List(ctx)
}
