// Package cli defines Warden's command tree and dispatches individual commands.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/containeroo/tinyflags"

	"github.com/gi8lino/keycloak-warden/internal/command/ban"
	"github.com/gi8lino/keycloak-warden/internal/command/endpoint"
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

	format := root.String("output", output.FormatText, "Output format").
		Choices(output.FormatText, output.FormatJSON, output.FormatYAML).
		Value()

	// Bind the flag value; the encoder reads it when a command runs, after parsing.
	encode := output.New(format, stdout)

	flags := endpoint.Register(root)
	serve.Register(root, flags, stdout, version)
	listactive.Register(root, encode)
	inspect.Register(root, encode)
	ban.Register(root, flags, encode)
	unban.Register(root, flags, encode)

	runner, err := root.ParseRunner(args)
	if err != nil {
		switch {
		case tinyflags.IsHelpRequested(err), tinyflags.IsVersionRequested(err):
			_, writeErr := fmt.Fprint(stdout, err.Error())
			return writeErr
		case tinyflags.IsCommandRequired(err):
			help, _ := tinyflags.HelpText(err)
			_, writeErr := fmt.Fprint(stderr, help)
			return writeErr
		default:
			if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
				return errors.Join(err, writeErr)
			}
			return err
		}
	}
	if err := runner.Run(ctx); err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return errors.Join(err, writeErr)
		}
		return err
	}
	return nil
}
