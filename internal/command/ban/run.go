// Package ban invokes the authenticated application API to create manual bans.
package ban

import (
	"context"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/command/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Run validates the requested IPs, prepares the client, and reports batch results.
func Run(
	ctx context.Context,
	applicationURL, token string,
	addresses []string,
	duration time.Duration,
	reason string,
	encode output.Encoder,
	opts ...client.Option,
) error {
	client, err := client.New(applicationURL, token, opts...)
	if err != nil {
		return err
	}

	batch, failures := execute(ctx, client, addresses, duration, reason)
	if err := encode(batch); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
