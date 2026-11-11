package listactive

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds authenticated remote active-ban listing and its flags.
func Register(root *tinyflags.Command, serverFlags appflags.ServerFlags, encode output.Encoder) {
	command := root.Command("list-active", "List active security decisions via the authenticated application API")
	command.HideEnvs()
	command.ExactPositional(0)
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")

	adminFlags := appflags.RegisterAdmin(command, serverFlags)

	command.Run(func(ctx context.Context) error {
		return Run(ctx, *adminFlags.ApplicationURL, *adminFlags.AdminToken, encode)
	})
}
