// Package ban invokes the authenticated application API to create manual bans.
package ban

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/command/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run applies a manual ban to each IP, continuing after individual API failures.
func Run(
	ctx context.Context,
	applicationURL, token string,
	inputs []string,
	duration time.Duration,
	reason string,
	encode output.Encoder,
) error {
	addresses, err := ipargs.Unique(inputs)
	if err != nil {
		return err
	}

	client, err := adminclient.New(applicationURL, token)
	if err != nil {
		return err
	}

	var failures []error
	batch := output.Batch{
		Operation: "ban",
		Results:   make([]output.Item, 0, len(addresses)),
	}

	for _, ip := range addresses {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}

		view, err := client.Ban(ctx, bans.ManualBanRequest{
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

		batch.Results = append(batch.Results, output.Item{IPAddress: ip, Success: true, Ban: &view})
		batch.Succeeded++
	}

	if err := encode(batch); err != nil {
		return errors.Join(append(failures, err)...)
	}

	return errors.Join(failures...)
}
