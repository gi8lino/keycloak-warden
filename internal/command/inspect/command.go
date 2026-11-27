package inspect

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/command/output"
)

// Register adds authenticated remote decision inspection and its flags.
func Register(
	root *tinyflags.Command,
	serverFlags *appflags.ServerFlags,
	encode output.Encoder,
) {
	command := root.Command("inspect", "Inspect security decisions by ID via the authenticated application API")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")
	command.MinPositional(1)

	adminFlags := appflags.RegisterAdmin(command, serverFlags)
	page := command.Int("history-page", 1, "One-based delivery-history page").
		Placeholder("NUMBER").
		OneOfGroup("history").
		Validate(tinyflags.Positive[int]()).
		Value()
	allFlag := command.Bool("history-all", false, "Fetch every delivery-history page").
		OneOfGroup("history").
		Value()

	command.Run(func(ctx context.Context) error {
		return Run(
			ctx,
			*adminFlags.ApplicationURL,
			*adminFlags.AdminToken,
			command.Args(),
			*page,
			*allFlag,
			encode,
			adminFlags.ClientOptions()...,
		)
	})
}
