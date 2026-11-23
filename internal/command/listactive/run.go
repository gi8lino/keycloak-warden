// Package listactive retrieves active decisions from Warden's authenticated HTTP API.
package listactive

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Run prepares the authenticated client and encodes the retrieved active decisions.
func Run(ctx context.Context, applicationURL, token string, encode output.Encoder, opts ...client.Option) error {
	client, err := client.New(applicationURL, token, opts...)
	if err != nil {
		return err
	}

	records, err := client.List(ctx)
	if err != nil {
		return err
	}

	return encode(records)
}
