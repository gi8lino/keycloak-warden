// Package unban invokes the authenticated application API to unblock IP addresses.
package unban

import (
	"context"
	"errors"
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/command/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Run resolves requested addresses to active decision IDs and reports batch results.
func Run(
	ctx context.Context,
	applicationURL, token string,
	addresses []string,
	encode output.Encoder,
	opts ...client.Option,
) error {
	client, err := client.New(applicationURL, token, opts...)
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
