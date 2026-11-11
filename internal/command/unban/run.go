// Package unban invokes the authenticated application API to unblock IP addresses.
package unban

import (
	"context"
	"errors"
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run resolves requested addresses to active decision IDs and reports batch results.
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

	batch, failures := execute(ctx, client, addresses, decisionIDsByIP(active))
	if err := encode(batch); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
