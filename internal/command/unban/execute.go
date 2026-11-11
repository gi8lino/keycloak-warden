package unban

import (
	"context"
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// execute releases each matching decision and records individual API failures.
func execute(
	ctx context.Context,
	client *adminclient.Client,
	addresses []string,
	ids map[string]string,
) (batch output.Batch, failures []error) {
	batch = output.Batch{
		Operation: "unban",
		Results:   make([]output.Item, 0, len(addresses)),
	}

	for _, ip := range addresses {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}

		id, exists := ids[ip]
		if !exists {
			failures = append(failures, fmt.Errorf("failed %s: %w", ip, bans.ErrNotFound))
			batch.Failed++
			batch.Results = append(batch.Results, output.Item{IPAddress: ip, Error: bans.ErrNotFound.Error()})
			continue
		}

		record, err := client.Unban(ctx, id)
		if err != nil {
			failures = append(failures, fmt.Errorf("failed %s: %w", ip, err))
			batch.Failed++
			batch.Results = append(batch.Results, output.Item{IPAddress: ip, Error: err.Error()})
			continue
		}

		batch.Results = append(batch.Results, output.Item{IPAddress: ip, Success: true, Ban: &record})
		batch.Succeeded++
	}

	return batch, failures
}

// decisionIDsByIP indexes active decisions for CLI address-based unban requests.
func decisionIDsByIP(records []bans.Record) map[string]string {
	ids := make(map[string]string, len(records))
	for _, record := range records {
		ids[record.Decision.IP] = record.Decision.ID
	}
	return ids
}
