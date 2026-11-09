package inspect

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds the read-only decision inspection command and its flags.
func Register(root *tinyflags.Command, encode output.Encoder) {
	command := root.Command("inspect", "Inspect security decisions by ID")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__DATABASE.")

	database := command.String("database", "warden.db", "SQLite database file").
		NotBlank().
		Value()

	command.MinPositional(1)
	command.Run(func(ctx context.Context) error {
		return Run(ctx, *database, command.Args(), encode)
	})
}
