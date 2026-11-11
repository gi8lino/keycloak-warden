// Package listactive retrieves active decisions from Warden's authenticated HTTP API.
package listactive

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run prepares the authenticated client and encodes the retrieved active decisions.
func Run(ctx context.Context, applicationURL, token string, encode output.Encoder) error {
	client, err := adminclient.New(applicationURL, token)
	if err != nil {
		return err
	}

	records, err := execute(ctx, client)
	if err != nil {
		return err
	}
	return encode(records)
}
