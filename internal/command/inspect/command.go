package inspect

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds the read-only decision inspection command and its flags.
func Register(root *tinyflags.Command, encode output.Encoder) {
	command := root.Command("inspect", "Inspect one security decision by ID")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN<FLAG_NAME> environment variables; for example WARDEN__DATABSE.")

	database := command.String("database", "warden.db", "SQLite database file").
		Value()

	command.ExactPositional(1)
	command.Run(func(ctx context.Context) error {
		args := command.Args()
		return Run(ctx, *database, args[0], encode)
	})
}
