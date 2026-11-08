package listactive

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds the read-only active-bans listing command and its flags.
func Register(root *tinyflags.Command, encode output.Encoder) {
	command := root.Command("list-active", "Print active security decisions")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__DATABSE.")

	database := command.String("database", "warden.db", "SQLite database file").
		Value()

	command.Run(func(ctx context.Context) error {
		return Run(ctx, *database, encode)
	})
}
