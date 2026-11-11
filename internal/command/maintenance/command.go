package maintenance

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds authenticated remote database maintenance commands to the Warden CLI.
func Register(root *tinyflags.Command, serverFlags appflags.ServerFlags, encode output.Encoder) {
	command := root.Command("maintenance", "Inspect and run database maintenance through the authenticated application API")
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")
	command.RequireCommand()
	command.HideEnvs()

	registerOperation(command, serverFlags, encode, ActionStatus, "Show the latest scheduled and manual maintenance results")
	registerOperation(command, serverFlags, encode, ActionPrune, "Prune expired login failure observations")
	registerOperation(command, serverFlags, encode, ActionOptimize, "Refresh SQLite query planner statistics")
}

// registerOperation binds one maintenance subcommand to the shared admin API flags.
func registerOperation(
	group *tinyflags.Command,
	serverFlags appflags.ServerFlags,
	encode output.Encoder,
	action Action,
	description string,
) {
	command := group.Command(string(action), description)
	command.HideEnvs()
	command.NoPositional()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")

	adminFlags := appflags.RegisterAdmin(command, serverFlags)

	command.Run(func(ctx context.Context) error {
		return Run(ctx, *adminFlags.ApplicationURL, *adminFlags.AdminToken, action, encode)
	})
}
