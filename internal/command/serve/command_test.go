package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containeroo/tinyflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// startupLogs executes the registered command against an occupied port and captures all startup logs.
func startupLogs(t *testing.T, args ...string) string {
	t.Helper()
	config := `
rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 2
      window: 1m
    actions:
      ban: 1m
enforcements:
  webhook:
    local:
      url: http://127.0.0.1:8090/hook
`
	output, err := runServeCommand(t, config, args...)
	require.ErrorContains(t, err, "address already in use")
	return output
}

// runServeCommand runs the registered command against an occupied application port.
func runServeCommand(t *testing.T, config string, args ...string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "warden.yaml")
	require.NoError(t, os.WriteFile(path, []byte(config), 0o600))

	occupied := httptest.NewServer(http.NotFoundHandler())
	defer occupied.Close()

	var output bytes.Buffer
	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.RegisterServer(root), &output, "test")
	commandArgs := []string{
		"serve",
		"--config", path,
		"--database", filepath.Join(dir, "warden.db"),
		"--listen-address", strings.TrimPrefix(occupied.URL, "http://"),
		"--management-listen-address=127.0.0.1:0",
		"--snitch-secret", "test-secret",
	}
	runner, err := root.ParseRunner(append(commandArgs, args...))
	require.NoError(t, err)
	err = runner.Run(t.Context())
	return strings.TrimSpace(output.String()), err
}

// startupLog returns the first startup record for log-format assertions.
func startupLog(t *testing.T, args ...string) string {
	t.Helper()
	return strings.SplitN(startupLogs(t, args...), "\n", 2)[0]
}

func TestLogFormat(t *testing.T) {
	t.Parallel()

	t.Run("text flag controls startup log", func(t *testing.T) {
		t.Parallel()

		line := startupLog(t, "--log-format=text")
		assert.Contains(t, line, "level=INFO")
		assert.Contains(t, line, `event=app_starting`)
		assert.False(t, json.Valid([]byte(line)))
	})

	t.Run("JSON is the default", func(t *testing.T) {
		t.Parallel()

		line := startupLog(t)
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		assert.Equal(t, "app_starting", record["event"])
	})

	t.Run("short flag selects JSON", func(t *testing.T) {
		t.Parallel()

		assert.True(t, json.Valid([]byte(startupLog(t, "-l", "json"))))
	})

	t.Run("unsupported format fails parsing", func(t *testing.T) {
		t.Parallel()

		root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
		Register(root, appflags.RegisterServer(root), &bytes.Buffer{}, "test")
		_, err := root.ParseRunner([]string{"serve", "--log-format", "xml"})
		require.Error(t, err)
	})
}

func TestLogFormatEnvironment(t *testing.T) {
	t.Setenv("WARDEN__LOG_FORMAT", "text")
	assert.Contains(t, startupLog(t), "level=INFO")
}

func TestServeFlagValidation(t *testing.T) {
	t.Parallel()

	parse := func(args ...string) error {
		root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
		Register(root, appflags.RegisterServer(root), &bytes.Buffer{}, "test")

		_, err := root.ParseRunner(append([]string{"serve"}, args...))
		return err
	}

	t.Run("requires Snitch secret", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse(), "snitch-secret")
	})

	t.Run("rejects empty Snitch secret", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret="), "snitch-secret")
	})

	t.Run("rejects whitespace Snitch secret", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", " \t "), "must not be blank")
	})

	t.Run("rejects empty config", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--config="), "config")
	})

	t.Run("rejects whitespace config", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--config", " 	 "), "must not be blank")
	})

	t.Run("rejects empty database", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--database="), "database")
	})

	t.Run("rejects whitespace database", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--database", " "), "must not be blank")
	})

	t.Run("rejects empty application listener", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--listen-address="), "listen-address")
	})

	t.Run("rejects whitespace application listener", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--listen-address", "  "), "--listen-address")
	})

	t.Run("rejects empty management listener without metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--management-listen-address="), "management-listen-address")
	})

	t.Run("rejects whitespace management listener without metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--management-listen-address", "   "), "--management-listen-address")
	})

	t.Run("rejects empty management listener with metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--metrics", "--management-listen-address="), "management-listen-address")
	})

	t.Run("rejects whitespace management listener with metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--metrics", "--management-listen-address", "   "), "--management-listen-address")
	})

	t.Run("rejects wildcard application listener with zero port", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--listen-address=:0"), "--listen-address")
	})

	t.Run("rejects wildcard management listener with zero port", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--management-listen-address=:0"), "--management-listen-address")
	})

	t.Run("allows explicit application IP with zero port", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret", "--listen-address=127.0.0.1:0"))
	})

	t.Run("allows explicitly configured management listener without metrics", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret", "--management-listen-address=127.0.0.1:0"))
	})

	t.Run("allows metrics with management listener", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret", "--metrics"))
	})

	t.Run("allows operational defaults with a Snitch secret", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret"))
	})

	t.Run("accepts maintenance interval overrides", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret", "--prune-interval=15m", "--optimize-interval=6h"))
	})

	t.Run("accepts minimum incident retention", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret", "--incident-retention=24h"))
	})

	t.Run("accepts maximum incident retention", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, parse("--snitch-secret", "secret", "--incident-retention=8760h"))
	})

	t.Run("rejects zero incident retention", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--incident-retention=0s"), "incident-retention")
	})

	t.Run("rejects negative incident retention", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--incident-retention=-24h"), "incident-retention")
	})

	t.Run("rejects retention shorter than one day", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--incident-retention=23h"), "incident-retention")
	})

	t.Run("rejects retention longer than one year", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--incident-retention=8761h"), "incident-retention")
	})

	t.Run("rejects retry delay flags", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--retry-initial-delay=2s"), "retry-initial-delay")
	})

	t.Run("rejects zero prune interval", func(t *testing.T) {
		t.Parallel()

		require.Error(t, parse("--snitch-secret", "secret", "--prune-interval=0"))
	})

	t.Run("rejects negative optimize interval", func(t *testing.T) {
		t.Parallel()

		require.Error(t, parse("--snitch-secret", "secret", "--optimize-interval=-1m"))
	})

	t.Run("rejects intervals beyond one year", func(t *testing.T) {
		t.Parallel()

		require.Error(t, parse("--snitch-secret", "secret", "--prune-interval=8761h"))
	})
}

func TestServeSecretEnvironment(t *testing.T) {
	t.Setenv("WARDEN__SNITCH_SECRET", "environment-secret")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.RegisterServer(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.NoError(t, err)
}

func TestServeRejectsBlankSecretEnvironment(t *testing.T) {
	t.Setenv("WARDEN__SNITCH_SECRET", "  ")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.RegisterServer(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.ErrorContains(t, err, "must not be blank")
}

func TestServeRejectsBlankManagementListenerEnvironment(t *testing.T) {
	t.Setenv("WARDEN__MANAGEMENT_LISTEN_ADDRESS", "  ")
	t.Setenv("WARDEN__SNITCH_SECRET", "test-secret")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.RegisterServer(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.ErrorContains(t, err, "WARDEN__MANAGEMENT_LISTEN_ADDRESS")
}

func TestMaintenanceIntervalEnvironment(t *testing.T) {
	t.Setenv("WARDEN__SNITCH_SECRET", "test-secret")
	t.Setenv("WARDEN__PRUNE_INTERVAL", "15m")
	t.Setenv("WARDEN__OPTIMIZE_INTERVAL", "6h")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.RegisterServer(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.NoError(t, err)
}

func TestIncidentRetention(t *testing.T) {
	t.Parallel()

	t.Run("uses default retention", func(t *testing.T) {
		t.Parallel()

		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(startupLog(t)), &record))
		assert.Equal(t, maintenance.DefaultIncidentRetention.String(), record["incident_retention"])
	})

	t.Run("uses configured retention", func(t *testing.T) {
		t.Parallel()

		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(startupLog(t, "--incident-retention=48h")), &record))
		assert.Equal(t, (48 * time.Hour).String(), record["incident_retention"])
	})
}

// TestIncidentRetentionEnvironment changes process-wide environment and cannot run in parallel.
func TestIncidentRetentionEnvironment(t *testing.T) {
	t.Setenv("WARDEN__INCIDENT_RETENTION", "168h")

	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(startupLog(t)), &record))
	assert.Equal(t, (168 * time.Hour).String(), record["incident_retention"])
}

// observeOnlyConfig is a valid detection rule without action destinations.
const observeOnlyConfig = `
rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 2
      window: 1m
    actions:
      ban: 1m
`

func TestObserveOnlyFlag(t *testing.T) {
	t.Parallel()

	t.Run("defaults to enforcement and requires a destination", func(t *testing.T) {
		t.Parallel()

		_, err := runServeCommand(t, observeOnlyConfig)
		require.ErrorContains(t, err, "automatic ban rules require at least one enforcement destination")
	})

	t.Run("allows startup without destinations", func(t *testing.T) {
		t.Parallel()

		logs, err := runServeCommand(t, observeOnlyConfig, "--observe-only")
		require.ErrorContains(t, err, "address already in use")
		assert.Contains(t, logs, `"observe_only":true`)
	})

	t.Run("does not resolve configured provider credentials", func(t *testing.T) {
		t.Parallel()

		cfg := observeOnlyConfig + `enforcements:
  webhook:
    local:
      url: file:/nonexistent/warden-observe-only-url
`
		_, err := runServeCommand(t, cfg, "--observe-only")
		require.ErrorContains(t, err, "address already in use")
	})

	t.Run("still rejects invalid target structure", func(t *testing.T) {
		t.Parallel()

		cfg := observeOnlyConfig + `enforcements:
  webhook:
    local:
      url: ""
`
		_, err := runServeCommand(t, cfg, "--observe-only")
		require.ErrorContains(t, err, "url: value must not be blank")
	})
}

func TestObserveOnlyEnvironment(t *testing.T) {
	// Environment changes are process-wide and cannot be used in parallel tests.
	t.Setenv("WARDEN__OBSERVE_ONLY", "true")

	logs, err := runServeCommand(t, observeOnlyConfig)
	require.ErrorContains(t, err, "address already in use")
	assert.Contains(t, logs, `"observe_only":true`)

	_, err = runServeCommand(t, observeOnlyConfig, "--observe-only=false")
	require.ErrorContains(t, err, "automatic ban rules require at least one enforcement destination")
}

func TestRetryDelayConfiguration(t *testing.T) {
	t.Parallel()

	t.Run("uses defaults", func(t *testing.T) {
		t.Parallel()

		line := startupLog(t)
		assert.Contains(t, line, `"retry_initial_delay":"10s"`)
		assert.Contains(t, line, `"retry_max_delay":"5m0s"`)
		assert.Contains(t, line, `"notification_retry_initial_delay":"10s"`)
	})

	t.Run("uses independent YAML overrides", func(t *testing.T) {
		t.Parallel()

		cfg := observeOnlyConfig + `enforcements:
  retry-initial-delay: 2s
  retry-max-delay: 30s
notifications:
  retry-initial-delay: 4s
  retry-max-delay: 1m
`
		logs, err := runServeCommand(t, cfg, "--observe-only")
		require.ErrorContains(t, err, "address already in use")
		assert.Contains(t, logs, `"retry_initial_delay":"2s"`)
		assert.Contains(t, logs, `"retry_max_delay":"30s"`)
		assert.Contains(t, logs, `"notification_retry_initial_delay":"4s"`)
		assert.Contains(t, logs, `"notification_retry_max_delay":"1m0s"`)
	})

	t.Run("rejects inverted delays before starting listeners", func(t *testing.T) {
		t.Parallel()

		cfg := observeOnlyConfig + `enforcements:
  retry-initial-delay: 20s
  retry-max-delay: 10s
`
		_, err := runServeCommand(t, cfg, "--observe-only")
		require.ErrorContains(t, err, "must not be less than retry-initial-delay")
	})

	t.Run("rejects submillisecond delays", func(t *testing.T) {
		t.Parallel()

		cfg := observeOnlyConfig + `enforcements:
  retry-initial-delay: 500us
`
		_, err := runServeCommand(t, cfg, "--observe-only")
		require.ErrorContains(t, err, "positive whole number of milliseconds")
	})
}
