package ban

import (
	"context"
	"fmt"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// execute attempts a manual ban for each address and retains per-address failures.
func execute(
	ctx context.Context,
	api *client.Client,
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

		record, err := api.Ban(ctx, client.ManualBanRequest{
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
