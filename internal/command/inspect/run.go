// Package inspect prints persisted decision records, sources, and delivery acknowledgements.
package inspect

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Run reads the requested decisions without modifying the SQLite database.
func Run(ctx context.Context, database string, ids []string, encode output.Encoder) error {
	views, err := sqlite.InspectMany(ctx, database, ids)
	if err != nil {
		return err
	}
	return encode(output.Records(views))
}
