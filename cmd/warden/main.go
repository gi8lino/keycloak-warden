// Command warden processes authenticated security events.
package main

import (
	"context"
	"os"

	"github.com/gi8lino/keycloak-warden/internal/cli"
)

// Version is set by the release build.
var Version = "dev"

// main executes the Warden CLI.
func main() {
	if err := cli.Run(context.Background(), os.Args[1:], Version, os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}
