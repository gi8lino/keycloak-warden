// Package inspect prints one persisted decision and its delivery acknowledgements.
package inspect

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Run reads the decision by ID without modifying the SQLite database.
func Run(ctx context.Context, database, id string, encode output.Encoder) error {
	view, err := sqlite.Inspect(ctx, database, id)
	if err != nil {
		return err
	}
	return encode(output.Inspection(view))
}
