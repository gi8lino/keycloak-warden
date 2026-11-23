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
	// HistoryPage is the one-based page returned for a single-page inspection.
	HistoryPage int `json:"historyPage,omitempty" yaml:"historyPage,omitempty"`
	// HistoryNextPage selects the next older page, when one exists.
	HistoryNextPage int `json:"historyNextPage,omitempty" yaml:"historyNextPage,omitempty"`
}

// inspectRecord uses detailed history when the server provides it.
func inspectRecord(record client.Record) inspection {
	view := inspection{
		Decision:        record.Decision,
		Sources:         record.Sources,
		Deliveries:      record.Deliveries,
		HistoryPage:     record.HistoryPage,
		HistoryNextPage: record.HistoryNextPage,
	}
	if record.HistoryPage != 0 || record.DeliveryHistory != nil {
		view.Deliveries = append([]client.Delivery{}, record.DeliveryHistory...)
	}
	return view
}

// execute fetches decisions in argument order, optionally including all history pages.
// A failure never produces partial encoded output.
func execute(ctx context.Context, api *client.Client, ids []string, page int, all bool) ([]inspection, error) {
	records := make([]inspection, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, err := api.GetPage(ctx, id, page)
		if err != nil {
			return nil, fmt.Errorf("inspect decision %q: %w", id, err)
		}

		if all {
			for record.HistoryNextPage != 0 {
				next := record.HistoryNextPage
				if next <= record.HistoryPage || len(record.DeliveryHistory) == 0 {
					return nil, fmt.Errorf("inspect decision %q: invalid history page sequence", id)
				}

				older, err := api.GetPageThroughRevision(ctx, id, next, record.Decision.Revision)
				if err != nil {
					return nil, fmt.Errorf("inspect decision %q history page %d: %w", id, next, err)
				}

				if older.HistoryPage != next {
					return nil, fmt.Errorf("inspect decision %q: invalid history page response", id)
				}

				record.DeliveryHistory = append(record.DeliveryHistory, older.DeliveryHistory...)
				record.HistoryPage = next
				record.HistoryNextPage = older.HistoryNextPage
			}
			record.HistoryPage = 0
		}
		records = append(records, inspectRecord(record))
	}

	return records, nil
}
