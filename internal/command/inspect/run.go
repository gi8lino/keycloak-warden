// Package inspect reads persisted decision records over the authenticated HTTP API.
package inspect

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run prepares an authenticated client and encodes decisions only after all reads succeed.
func Run(ctx context.Context, applicationURL, token string, ids []string, encode output.Encoder) error {
	client, err := adminclient.New(applicationURL, token)
	if err != nil {
		return err
	}

	records, err := execute(ctx, client, ids)
	if err != nil {
		return err
	}
	return encode(records)
}
