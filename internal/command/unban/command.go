package unban

import (
	"context"

	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/keycloak-warden/internal/command/endpoint"

	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds the authenticated unban command and its flags.
func Register(root *tinyflags.Command, flags endpoint.Flags, encode output.Encoder) {
	command := root.Command("unban", "Unblock one or more IP addresses via the authenticated application API")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")

	applicationURL := flags.ApplicationURLFlag(command)
	token := command.String("admin-token", "", "Application API administrator bearer token").
		Placeholder("SECRET").
		OverriddenValueMaskFn(tinyflags.MaskFirstLast).
		Value()

	command.MinPositional(1)
	command.SetPositionalValidate(ipargs.Validate)
	command.Run(func(ctx context.Context) error {
		return Run(ctx, *applicationURL, *token, command.Args(), encode)
	})
}
