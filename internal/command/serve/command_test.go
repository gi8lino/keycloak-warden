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

	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/keycloak-warden/internal/command/appflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startupLogs executes the registered command against an occupied port and captures all startup logs.
func startupLogs(t *testing.T, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "warden.yaml")
	config := `
rule:
  threshold: 2
  window: 1m
  ban: 1m
targets:
  webhook:
    local:
      url: http://127.0.0.1:8090/hook
`
	require.NoError(t, os.WriteFile(path, []byte(config), 0o600))

	occupied := httptest.NewServer(http.NotFoundHandler())
	defer occupied.Close()

	var output bytes.Buffer
	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.Register(root), &output, "test")
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
	require.ErrorContains(t, runner.Run(t.Context()), "address already in use")
	return strings.TrimSpace(output.String())
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
		Register(root, appflags.Register(root), &bytes.Buffer{}, "test")
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
		Register(root, appflags.Register(root), &bytes.Buffer{}, "test")

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

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--listen-address", "  "), "must not be blank")
	})

	t.Run("rejects empty management listener without metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--management-listen-address="), "management-listen-address")
	})

	t.Run("rejects whitespace management listener without metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--management-listen-address", "   "), "must not be blank")
	})

	t.Run("rejects empty management listener with metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--metrics", "--management-listen-address="), "management-listen-address")
	})

	t.Run("rejects whitespace management listener with metrics", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, parse("--snitch-secret", "secret", "--metrics", "--management-listen-address", "   "), "must not be blank")
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
	Register(root, appflags.Register(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.NoError(t, err)
}

func TestServeRejectsBlankSecretEnvironment(t *testing.T) {
	t.Setenv("WARDEN__SNITCH_SECRET", "  ")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.Register(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.ErrorContains(t, err, "must not be blank")
}

func TestServeRejectsBlankManagementListenerEnvironment(t *testing.T) {
	t.Setenv("WARDEN__MANAGEMENT_LISTEN_ADDRESS", "  ")
	t.Setenv("WARDEN__SNITCH_SECRET", "test-secret")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.Register(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.ErrorContains(t, err, "must not be blank")
}

func TestMaintenanceIntervalEnvironment(t *testing.T) {
	t.Setenv("WARDEN__SNITCH_SECRET", "test-secret")
	t.Setenv("WARDEN__PRUNE_INTERVAL", "15m")
	t.Setenv("WARDEN__OPTIMIZE_INTERVAL", "6h")

	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, appflags.Register(root), &bytes.Buffer{}, "test")

	_, err := root.ParseRunner([]string{"serve"})
	require.NoError(t, err)
}
