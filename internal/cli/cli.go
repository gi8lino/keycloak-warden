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
	"github.com/gi8lino/keycloak-warden/internal/command/maintenance"
	"github.com/gi8lino/keycloak-warden/internal/command/output"
	"github.com/gi8lino/keycloak-warden/internal/command/retrydelivery"
	"github.com/gi8lino/keycloak-warden/internal/command/serve"
	"github.com/gi8lino/keycloak-warden/internal/command/unban"
)

// Run parses and executes one Warden command.
func Run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) error {
	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError).RequireCommand()
	root.Version(version)
	root.EnvPrefix("WARDEN_")
	root.HideEnvs()
	root.Note("\nFlags can also be set using WARDEN__<FLAG_NAME> environment variables; for example WARDEN__LISTEN_ADDRESS.")

	format := root.String("output", "", "Detailed output format (default: concise ban/unban, YAML for queries)").
		Section("Output").
		OneOfGroup("output-mode").
		HideDefault().
		Choices(output.FormatText, output.FormatJSON, output.FormatYAML).
		Short("o").
		Value()

	quiet := root.Bool("quiet", false, "Suppress successful command output").
		Section("Output").
		Short("q").
		OneOfGroup("output-mode").
		Value()

	// Bind the flag value; the encoder reads it when a command runs, after parsing.
	encode := output.NewPrinter(format, quiet, stdout)

	serverFlags := appflags.RegisterServer(root)

	serve.Register(root, serverFlags, stdout, version)
	listactive.Register(root, serverFlags, encode)
	inspect.Register(root, serverFlags, encode)
	ban.Register(root, serverFlags, encode)
	unban.Register(root, serverFlags, encode)
	maintenance.Register(root, serverFlags, encode)
	retrydelivery.Register(root, serverFlags, encode)

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
