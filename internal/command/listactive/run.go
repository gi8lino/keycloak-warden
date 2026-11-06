// Package listactive prints active decisions with their ban sources.
package listactive

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/output"

	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// Run lists active decisions and their sources without modifying SQLite.
func Run(ctx context.Context, database string, encode output.Encoder) error {
	active, err := sqlite.ListActiveBans(ctx, database, time.Now())
	if err != nil {
		return err
	}
	return encode(output.Bans(active))
}
