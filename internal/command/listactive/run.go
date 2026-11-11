// Package listactive retrieves active decisions from Warden's authenticated HTTP API.
package listactive

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run retrieves current active bans through the application API and encodes the result.
func Run(ctx context.Context, applicationURL, token string, encode output.Encoder) error {
	client, err := adminclient.New(applicationURL, token)
	if err != nil {
		return err
	}
	records, err := client.List(ctx)
	if err != nil {
		return err
	}
	return encode(records)
}
