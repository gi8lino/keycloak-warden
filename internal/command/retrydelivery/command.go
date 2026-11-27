// Package retrydelivery exposes authenticated explicit delivery retries.
package retrydelivery

import (
	"context"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/command/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Register binds one decision ID and destination to a revision-guarded retry request.
func Register(root *tinyflags.Command, serverFlags *appflags.ServerFlags, encode output.Encoder) {
	command := root.Command("retry-delivery", "Retry an exhausted delivery by decision ID and destination")
	command.HideEnvs()
	command.Note("\nArguments: DECISION_ID DESTINATION. Flags can also be set using WARDEN__<FLAG_NAME> environment variables.")
	command.ExactPositional(2)

	adminFlags := appflags.RegisterAdmin(command, serverFlags)
	revision := command.Int("revision", 0, "Expected current decision revision").Required().Validate(tinyflags.Positive[int]()).Value()
	actor := command.String("actor", "", "Operator identity for the retry audit record").Required().NotBlank().Value()

	command.Run(func(ctx context.Context) error {
		args := command.Args()
		return Run(ctx, *adminFlags.ApplicationURL, *adminFlags.AdminToken, client.RetryRequest{
			DecisionID:  args[0],
			Revision:    int64(*revision),
			Destination: args[1],
			Actor:       *actor,
		}, encode, adminFlags.ClientOptions()...)
	})
}
