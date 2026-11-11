// Package cli defines Warden's command tree and dispatches individual commands.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/command/ban"
	"github.com/gi8lino/keycloak-warden/internal/command/inspect"
	"github.com/gi8lino/keycloak-warden/internal/command/listactive"
	"github.com/gi8lino/keycloak-warden/internal/command/serve"
	"github.com/gi8lino/keycloak-warden/internal/command/unban"
	"github.com/gi8lino/keycloak-warden/internal/output"
)

// Run parses and executes one Warden command.
func Run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) error {
	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError).RequireCommand()
	root.Version(version)
	root.EnvPrefix("WARDEN_")
	root.HideEnvs()
	root.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__LISTEN_ADDRESS.")

	format := root.String("output", output.FormatYAML, "Output format").
		Choices(output.FormatText, output.FormatJSON, output.FormatYAML).
		Value()

	// Bind the flag value; the encoder reads it when a command runs, after parsing.
	encode := output.New(format, stdout)

	flags := appflags.Register(root)
	serve.Register(root, flags, stdout, version)
	listactive.Register(root, encode)
	inspect.Register(root, encode)
	ban.Register(root, flags, encode)
	unban.Register(root, flags, encode)

	runner, err := root.ParseRunner(args)
	if err != nil {
		switch {
		case tinyflags.IsHelpRequested(err), tinyflags.IsVersionRequested(err):
			fmt.Fprint(stdout, err.Error()) // nolint:errcheck
			return nil
		case tinyflags.IsCommandRequired(err):
			help, _ := tinyflags.HelpText(err)
			fmt.Fprint(stderr, help) // nolint:errcheck
			return err
		default:
			fmt.Fprintln(stderr, err) // nolint:errcheck
			return err
		}
	}
	if err := runner.Run(ctx); err != nil {
		fmt.Fprintln(stderr, err) // nolint:errcheck
		return err
	}

	return nil
}
