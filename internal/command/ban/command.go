package ban

import (
	"context"
	"fmt"
	"strings"

	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/keycloak-warden/internal/command/appflags"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"

	"github.com/gi8lino/keycloak-warden/internal/command/ipargs"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Register adds the authenticated manual-ban command and its flags.
func Register(root *tinyflags.Command, flags appflags.Flags, encode output.Encoder) {
	command := root.Command("ban", "Manually ban one or more IP addresses via the authenticated application API")
	command.HideEnvs()
	command.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__ADMIN_TOKEN.")

	applicationURL := flags.ApplicationURLFlag(command)
	token := appflags.AdminTokenFlag(command)
	duration := command.Duration("duration", 0, "Manual ban lifetime").
		Required().
		Validate(tinyflags.Between(bans.MinDuration, bans.MaxDuration)).
		Value()
	reason := command.String("reason", "", "Operator explanation").
		Required().
		Validate(validateReason).
		Value()

	command.MinPositional(1)
	command.SetPositionalValidate(ipargs.Validate)
	command.Run(func(ctx context.Context) error {
		return Run(ctx, *applicationURL, *token, command.Args(), *duration, *reason, encode)
	})
}

// validateReason rejects blank or oversized manual ban explanations during flag parsing.
func validateReason(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > bans.MaxReasonLength {
		return fmt.Errorf("reason must contain 1–%d bytes of nonblank text", bans.MaxReasonLength)
	}
	return nil
}
