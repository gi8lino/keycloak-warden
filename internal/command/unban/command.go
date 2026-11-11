package unban

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds the authenticated unban command and its flags.
func Register(root *tinyflags.Command, serverFlags appflags.ServerFlags, encode output.Encoder) {
	command := root.Command("unban", "Unblock one or more IP addresses via the authenticated application API")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")
	command.MinPositional(1)
	command.SetPositionalValidate(ipargs.Validate)

	adminFlags := appflags.RegisterAdmin(command, serverFlags)

	command.Run(func(ctx context.Context) error {
		return Run(ctx, *adminFlags.ApplicationURL, *adminFlags.AdminToken, command.Args(), encode)
	})
}
