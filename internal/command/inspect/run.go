// Package inspect reads persisted decision records over the authenticated HTTP API.
package inspect

import (
	"context"
	"errors"

	"github.com/gi8lino/keycloak-warden/internal/command/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Run retrieves decisions and encodes a selected history page or all pages.
func Run(
	ctx context.Context,
	applicationURL, token string,
	ids []string,
	page int,
	all bool,
	encode output.Encoder,
	opts ...client.Option,
) error {
	if page < 1 {
		return errors.New("history-page must be a positive integer")
	}
	if all && page != 1 {
		return errors.New("history-page and history-all cannot be combined")
	}

	api, err := client.New(applicationURL, token, opts...)
	if err != nil {
		return err
	}

	records, err := execute(ctx, api, ids, page, all)
	if err != nil {
		return err
	}

	return encode(records)
}
