// Package inspect reads persisted decision records over the authenticated HTTP API.
package inspect

import (
	"context"
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run retrieves requested decisions in argument order and emits output only if all requests succeed.
func Run(ctx context.Context, applicationURL, token string, ids []string, encode output.Encoder) error {
	client, err := adminclient.New(applicationURL, token)
	if err != nil {
		return err
	}

	records := make([]bans.Record, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := client.Get(ctx, id)
		if err != nil {
			return fmt.Errorf("inspect decision %q: %w", id, err)
		}
		records = append(records, record)
	}
	return encode(records)
}
