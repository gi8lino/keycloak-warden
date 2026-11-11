// Package listactive prints active decisions with their ban sources.
package listactive

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/output"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Run lists active decision records including sources and deliveries without modifying SQLite.
func Run(ctx context.Context, database string, encode output.Encoder) error {
	records, err := sqlite.ListActiveBans(ctx, database, time.Now())
	if err != nil {
		return err
	}
	return encode(records)
}
