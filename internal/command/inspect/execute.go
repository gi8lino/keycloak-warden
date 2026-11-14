package inspect

import (
	"context"
	"fmt"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// inspection presents revision history under deliveries in CLI output.
type inspection struct {
	// Decision is the latest desired state.
	Decision client.Decision `json:"decision" yaml:"decision"`
	// Sources are the currently active ban sources.
	Sources []client.Source `json:"sources" yaml:"sources"`
	// Deliveries groups attempts by revision, or shows acknowledgements from older servers.
	Deliveries any `json:"deliveries" yaml:"deliveries"`
}

// inspectRecord uses detailed history when the server provides it.
func inspectRecord(record client.Record) inspection {
	view := inspection{Decision: record.Decision, Sources: record.Sources, Deliveries: record.Deliveries}
	if record.DeliveryHistory != nil {
		view.Deliveries = record.DeliveryHistory
	}
	return view
}

// execute fetches decisions in argument order and fails without returning a partial result.
func execute(ctx context.Context, api *client.Client, ids []string) ([]inspection, error) {
	records := make([]inspection, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		record, err := api.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("inspect decision %q: %w", id, err)
		}
		records = append(records, inspectRecord(record))
	}
	return records, nil
}
