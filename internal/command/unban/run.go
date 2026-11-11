// Package unban invokes the authenticated application API to unblock IP addresses.
package unban

import (
	"context"
	"errors"
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run removes all active ban sources from each IP, continuing after individual API failures.
func Run(ctx context.Context, applicationURL, token string, inputs []string, encode output.Encoder) error {
	addresses, err := ipargs.Unique(inputs)
	if err != nil {
		return err
	}

	client, err := adminclient.New(applicationURL, token)
	if err != nil {
		return err
	}

	active, err := client.List(ctx)
	if err != nil {
		return fmt.Errorf("list active bans: %w", err)
	}

	ids := make(map[string]string, len(active))
	for _, view := range active {
		ids[view.Decision.IP] = view.Decision.ID
	}

	var failures []error
	batch := output.Batch{Operation: "unban", Results: make([]output.Item, 0, len(addresses))}
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

		view, err := client.Unban(ctx, id)
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
