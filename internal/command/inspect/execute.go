package inspect

import (
	"context"
	"fmt"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// execute fetches decisions in argument order and fails without returning a partial result.
func execute(ctx context.Context, api *client.Client, ids []string) ([]client.Record, error) {
	records := make([]client.Record, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		record, err := api.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("inspect decision %q: %w", id, err)
		}
		records = append(records, record)
	}
	return records, nil
}
