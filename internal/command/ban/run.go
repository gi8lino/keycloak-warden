// Package ban invokes the authenticated application API to create manual bans.
package ban

import (
	"context"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Run validates the requested IPs, prepares the client, and reports batch results.
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

	client, err := client.New(applicationURL, token)
	if err != nil {
		return err
	}

	batch, failures := execute(ctx, client, addresses, duration, reason)
	if err := encode(batch); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
