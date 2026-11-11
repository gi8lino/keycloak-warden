package ban

import (
	"context"
	"fmt"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// execute attempts a manual ban for each address and retains per-address failures.
func execute(
	ctx context.Context,
	client *adminclient.Client,
	addresses []string,
	duration time.Duration,
	reason string,
) (batch output.Batch, failures []error) {
	batch = output.Batch{
		Operation: "ban",
		Results:   make([]output.Item, 0, len(addresses)),
	}

	for _, ip := range addresses {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}

		record, err := client.Ban(ctx, bans.ManualBanRequest{
			IP:       ip,
			Duration: duration,
			Reason:   reason,
		})
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
