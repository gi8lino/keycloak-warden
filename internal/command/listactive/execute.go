package listactive

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// execute fetches current active bans from the authenticated application API.
func execute(ctx context.Context, client *adminclient.Client) ([]bans.Record, error) {
	return client.List(ctx)
}
