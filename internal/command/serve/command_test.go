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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startupLog executes the registered command against an occupied port and captures its startup log.
func startupLog(t *testing.T, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "warden.yaml")
	require.NoError(t, os.WriteFile(path, []byte("rule:\n  threshold: 2\n  window: 1m\n  ban: 1m\n"), 0o600))

	occupied := httptest.NewServer(http.NotFoundHandler())
	defer occupied.Close()

	var output bytes.Buffer
	root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
	root.EnvPrefix("WARDEN_")
	Register(root, &output, "test")
	commandArgs := []string{
		"serve", "--config", path, "--database", filepath.Join(dir, "warden.db"),
		"--listen-address", strings.TrimPrefix(occupied.URL, "http://"),
		"--management-listen-address=", "--snitch-secret", "test-secret",
	}
	runner, err := root.ParseRunner(append(commandArgs, args...))
	require.NoError(t, err)
	require.ErrorContains(t, runner.Run(t.Context()), "address already in use")
	return strings.SplitN(strings.TrimSpace(output.String()), "\n", 2)[0]
}

func TestLogFormat(t *testing.T) {
	t.Parallel()
	t.Run("text flag controls startup log", func(t *testing.T) {
		t.Parallel()
		line := startupLog(t, "--log-format=text")
		assert.Contains(t, line, "level=INFO")
		assert.Contains(t, line, `msg="starting Warden"`)
		assert.False(t, json.Valid([]byte(line)))
	})
	t.Run("JSON is the default", func(t *testing.T) {
		t.Parallel()
		line := startupLog(t)
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		assert.Equal(t, "starting Warden", record["msg"])
	})
	t.Run("short flag selects JSON", func(t *testing.T) {
		t.Parallel()
		assert.True(t, json.Valid([]byte(startupLog(t, "-l", "json"))))
	})
	t.Run("unsupported format fails parsing", func(t *testing.T) {
		t.Parallel()
		root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
		Register(root, &bytes.Buffer{}, "test")
		_, err := root.ParseRunner([]string{"serve", "--log-format", "xml"})
		require.Error(t, err)
	})
}

func TestLogFormatEnvironment(t *testing.T) {
	t.Setenv("WARDEN__LOG_FORMAT", "text")
	assert.Contains(t, startupLog(t), "level=INFO")
}

func TestDebugLogging(t *testing.T) {
	t.Parallel()
	line := startupLog(t, "--debug", "--log-format=text")
	assert.Contains(t, line, "level=DEBUG")
	assert.Contains(t, line, `msg="configuration loaded"`)
}

func TestDebugEnvironment(t *testing.T) {
	t.Setenv("WARDEN__DEBUG", "true")
	assert.Contains(t, startupLog(t), `"level":"DEBUG"`)
}
