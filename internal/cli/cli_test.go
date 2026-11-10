package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("missing command prints root help and returns error", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer

		err := Run(t.Context(), nil, "test", io.Discard, &stderr)
		require.ErrorContains(t, err, "requires a subcommand")
		assert.Contains(t, stderr.String(), "serve")
		assert.Contains(t, stderr.String(), "ban")
		assert.Contains(t, stderr.String(), "unban")
		assert.Contains(t, stderr.String(), "list-active")
		assert.Contains(t, stderr.String(), "inspect")
		assert.Contains(t, stderr.String(), "--listen-address")
		assert.Contains(t, stderr.String(), "--route-prefix")
	})

	t.Run("serve help contains operational flags", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		require.NoError(t, Run(t.Context(), []string{"serve", "--help"}, "test", &stdout, io.Discard))
		assert.Contains(t, stdout.String(), "--snitch-secret")
		assert.Contains(t, stdout.String(), "--admin-token")
		assert.NotContains(t, stdout.String(), "--management-token")
		assert.Contains(t, stdout.String(), "--access-log")
		assert.Contains(t, stdout.String(), "--metrics")
		assert.Contains(t, stdout.String(), "--management-listen-address")
		assert.Contains(t, stdout.String(), "--database")
		assert.Contains(t, stdout.String(), "--config")
	})

	t.Run("serve rejects an invalid route prefix during parsing", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"serve",
			"--route-prefix", "/warden/../api",
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "route prefix")
		assert.Contains(t, stderr.String(), "route-prefix")
	})

	t.Run("inspect help requires only database", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		require.NoError(t, Run(t.Context(), []string{"inspect", "--help"}, "test", &stdout, io.Discard))
		assert.Contains(t, stdout.String(), "--database")
		assert.NotContains(t, stdout.String(), "--config")
		assert.NotContains(t, stdout.String(), "--snitch-secret")
	})

	t.Run("list-active help requires only database", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		require.NoError(t, Run(t.Context(), []string{"list-active", "--help"}, "test", &stdout, io.Discard))
		assert.Contains(t, stdout.String(), "--database")
		assert.NotContains(t, stdout.String(), "--config")
	})

	t.Run("inspect rejects missing ID", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{"inspect"}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "positional")
		assert.Contains(t, stderr.String(), "positional")
	})

	t.Run("serve requires readable config", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		missing := filepath.Join(t.TempDir(), "missing.yaml")
		err := Run(t.Context(), []string{
			"serve",
			"--config", missing,
			"--snitch-secret", "test-secret",
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "missing.yaml")
		assert.Contains(t, stderr.String(), "missing.yaml")
	})

	t.Run("serve rejects operational settings in YAML", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.yaml")

		require.NoError(t, os.WriteFile(
			path,
			[]byte("listen-address: 127.0.0.1:8081\nrule:\n  threshold: 2\n  window: 1m\n  ban: 15m\n"),
			0o600,
		))
		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"serve",
			"--config", path,
			"--snitch-secret", "test-secret",
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("serve validates the secret", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.yaml")

		require.NoError(t, os.WriteFile(path, []byte("rule:\n  threshold: 2\n  window: 1m\n  ban: 15m\n"), 0o600))
		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"serve",
			"--config", path,
			"--listen-address", "127.0.0.1:8081",
			"--database", "warden.db",
			"--snitch-secret", "",
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "snitch-secret")
	})

	t.Run("ban flags stay command scoped", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		require.NoError(t, Run(t.Context(), []string{"ban", "--help"}, "test", &stdout, io.Discard))
		assert.Contains(t, stdout.String(), "--admin-token")
		assert.Contains(t, stdout.String(), "--application-url")
		assert.NotContains(t, stdout.String(), "--management-url")
		assert.NotContains(t, stdout.String(), "--database")
		assert.NotContains(t, stdout.String(), "--config")
	})

	t.Run("unban flags stay command scoped", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		require.NoError(t, Run(t.Context(), []string{"unban", "--help"}, "test", &stdout, io.Discard))
		assert.Contains(t, stdout.String(), "--admin-token")
		assert.Contains(t, stdout.String(), "--application-url")
		assert.NotContains(t, stdout.String(), "--management-url")
		assert.NotContains(t, stdout.String(), "--database")
		assert.NotContains(t, stdout.String(), "--config")
	})

	t.Run("ban rejects invalid application URL during flag parsing", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.1",
			"--duration", "1h",
			"--reason", "test",
			"--application-url", "http://warden:8081",
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "HTTPS")
		assert.Contains(t, stderr.String(), "application-url")
	})

	t.Run("unban rejects invalid application URL during flag parsing", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"unban", "203.0.113.1",
			"--application-url", "http://warden:8081",
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "HTTPS")
		assert.Contains(t, stderr.String(), "application-url")
	})

	t.Run("output flag supports json after ban command", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"decision":{"id":"stable","ipAddress":"203.0.113.10"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10",
			"--duration", "1h",
			"--reason", "Incident",
			"--application-url", server.URL,
			"--admin-token", "secret",
			"--output", "json",
		}, "test", &stdout, &stderr)

		require.NoError(t, err, stderr.String())
		var result struct {
			// Operation identifies the requested administrative action.
			Operation string `json:"operation"`
			// Results contains the outcome for each requested address.
			Results []struct {
				// IPAddress is the canonical address selected by the operation.
				IPAddress string `json:"ipAddress"`
				// Success reports whether this address operation succeeded.
				Success bool `json:"success"`
				// Ban is the resulting ban view returned by the operation.
				Ban struct {
					// Decision contains the effective desired state for the address.
					Decision struct {
						// ID identifies the event or decision in this response.
						ID string `json:"id"`
					} `json:"decision"`
				} `json:"ban"`
			} `json:"results"`
			// Succeeded counts successful address operations.
			Succeeded int `json:"succeeded"`
		}

		require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
		assert.Equal(t, "ban", result.Operation)
		assert.Equal(t, 1, result.Succeeded)
		require.Len(t, result.Results, 1)
		assert.Equal(t, "203.0.113.10", result.Results[0].IPAddress)
		assert.True(t, result.Results[0].Success)
		assert.Equal(t, "stable", result.Results[0].Ban.Decision.ID)
	})

	t.Run("output flag supports yaml before unban command", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`[{"decision":{"id":"stable","ipAddress":"203.0.113.10"},"sources":[],"deliveries":[]}]`))
				return
			}
			_, _ = w.Write([]byte(`{"decision":{"id":"stable","ipAddress":"203.0.113.10","state":"unbanned"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"--output", "yaml",
			"unban", "203.0.113.10",
			"--application-url", server.URL,
			"--admin-token", "secret",
		}, "test", &stdout, &stderr)

		require.NoError(t, err, stderr.String())
		var result struct {
			// Operation identifies the requested administrative action.
			Operation string `yaml:"operation"`
			// Succeeded counts successful address operations.
			Succeeded int `yaml:"succeeded"`
			// Results contains the outcome for each requested address.
			Results []struct {
				// IPAddress is the canonical address selected by the operation.
				IPAddress string `yaml:"ipAddress"`
				// Success reports whether this address operation succeeded.
				Success bool `yaml:"success"`
			} `yaml:"results"`
		}

		require.NoError(t, yaml.Load(stdout.Bytes(), &result))
		assert.Equal(t, "unban", result.Operation)
		assert.Equal(t, 1, result.Succeeded)
		require.Len(t, result.Results, 1)
		assert.Equal(t, "203.0.113.10", result.Results[0].IPAddress)
		assert.True(t, result.Results[0].Success)
	})

	t.Run("rejects unsupported output format during flag parsing", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10",
			"--duration", "1h",
			"--reason", "Incident",
			"--output", "xml",
		}, "test", io.Discard, &stderr)

		require.Error(t, err)
		assert.Contains(t, stderr.String(), "xml")
	})

	t.Run("root output flag appears in help", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		require.NoError(t, Run(t.Context(), []string{"--help"}, "test", &stdout, io.Discard))
		assert.Contains(t, stdout.String(), "--output")
	})

	t.Run("ban requires at least one positional IP", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban",
			"--duration", "1h",
			"--reason", "incident",
		}, "test", io.Discard, &stderr)

		require.Error(t, err)
		assert.NotEmpty(t, stderr.String())
	})

	t.Run("unban requires at least one positional IP", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{"unban"}, "test", io.Discard, &stderr)

		require.Error(t, err)
		assert.NotEmpty(t, stderr.String())
	})

	t.Run("ban rejects invalid IP before sending a request", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10", "not-an-ip",
			"--duration", "1h",
			"--reason", "incident",
			"--admin-token", "admin",
			"--application-url", server.URL,
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "not-an-ip")
		assert.Zero(t, requests.Load())
	})

	t.Run("unban rejects invalid IP before sending a request", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"unban", "203.0.113.10", "not-an-ip",
			"--admin-token", "admin",
			"--application-url", server.URL,
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "not-an-ip")
		assert.Zero(t, requests.Load())
	})

	t.Run("ban canonicalizes and deduplicates addresses before requesting", func(t *testing.T) {
		t.Parallel()

		var received []string
		var receivedMu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload struct {
				// IP is the reported client address, which may be absent in an event.
				IP string `json:"ipAddress"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			receivedMu.Lock()
			received = append(received, payload.IP)
			receivedMu.Unlock()
			_, _ = w.Write([]byte(`{"decision":{"id":"stable"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "::ffff:203.0.113.10", "203.0.113.10", "203.0.113.20",
			"--duration", "1h",
			"--reason", "incident",
			"--admin-token", "admin",
			"--application-url", server.URL,
		}, "test", &stdout, &stderr)

		require.NoError(t, err, stderr.String())
		receivedMu.Lock()
		assert.Equal(t, []string{"203.0.113.10", "203.0.113.20"}, received)
		receivedMu.Unlock()

		assert.Contains(t, stdout.String(), "2 succeeded, 0 failed")
	})

	t.Run("unban canonicalizes and deduplicates addresses before requesting", func(t *testing.T) {
		t.Parallel()

		var deletes atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`[{"decision":{"id":"stable","ipAddress":"203.0.113.10"}}]`))
			case http.MethodDelete:
				deletes.Add(1)

				assert.Equal(t, "/bans/stable", r.URL.Path)
				_, _ = w.Write([]byte(`{"decision":{"state":"unbanned"},"sources":[],"deliveries":[]}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"unban", "::ffff:203.0.113.10", "203.0.113.10",
			"--admin-token", "admin",
			"--application-url", server.URL,
		}, "test", &stdout, &stderr)

		require.NoError(t, err, stderr.String())
		assert.EqualValues(t, 1, deletes.Load())
		assert.Contains(t, stdout.String(), "1 succeeded, 0 failed")
	})

	t.Run("ban rejects blank reason during flag parsing", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10",
			"--duration", "1h",
			"--reason", "   ",
		}, "test", io.Discard, &stderr)

		require.Error(t, err)
		assert.NotEmpty(t, stderr.String())
	})

	t.Run("ban rejects a duration shorter than one second", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10",
			"--duration", "500ms",
			"--reason", "incident",
		}, "test", io.Discard, &stderr)

		require.Error(t, err)
		assert.NotEmpty(t, stderr.String())
	})

	t.Run("unban rejects decision IDs as positional input", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{"unban", "decision-uuid"}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "decision-uuid")
		assert.NotEmpty(t, stderr.String())
	})

	t.Run("ban rejects an overlong reason before sending a request", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10",
			"--duration", "1h",
			"--reason", strings.Repeat("x", bans.MaxReasonLength+1),
		}, "test", io.Discard, &stderr)

		require.ErrorContains(t, err, "reason")
		assert.NotEmpty(t, stderr.String())
	})

	t.Run("ban rejects excessive duration before sending a request", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer
		err := Run(t.Context(), []string{
			"ban", "203.0.113.10",
			"--duration", "744h",
			"--reason", "incident",
		}, "test", io.Discard, &stderr)

		require.Error(t, err)
		assert.NotEmpty(t, stderr.String())
	})
}

// inspectTestDatabase creates two persisted decisions for CLI inspection tests.
func inspectTestDatabase(t *testing.T) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.db")
	store, err := sqlite.Open(path, detection.Rule{Threshold: 2, Window: time.Minute, Ban: time.Minute}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	service, err := bans.NewAdminService(store)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Millisecond)
	first, err := service.BanManual(t.Context(), bans.ManualBanRequest{IP: "203.0.113.10", Duration: time.Hour, Reason: "incident one"}, now)
	require.NoError(t, err)
	second, err := service.BanManual(t.Context(), bans.ManualBanRequest{IP: "203.0.113.11", Duration: time.Hour, Reason: "incident two"}, now)
	require.NoError(t, err)
	return path, []string{first.Decision.ID, second.Decision.ID}
}

func TestInspectMultiple(t *testing.T) {
	t.Parallel()

	t.Run("text displays multiple decisions", func(t *testing.T) {
		t.Parallel()
		path, ids := inspectTestDatabase(t)
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{"inspect", ids[1], ids[0], "--database", path}, "test", &stdout, &stderr)
		require.NoError(t, err, stderr.String())
		first := strings.Index(stdout.String(), "ID: "+ids[1])
		second := strings.Index(stdout.String(), "ID: "+ids[0])
		assert.GreaterOrEqual(t, first, 0)
		assert.Greater(t, second, first)
		assert.Contains(t, stdout.String(), "Deliveries: none\n\nID: "+ids[0])
	})

	t.Run("JSON always returns an array, including for one ID", func(t *testing.T) {
		t.Parallel()
		path, ids := inspectTestDatabase(t)
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{"inspect", ids[0], "--database", path, "--output", "json"}, "test", &stdout, &stderr)
		require.NoError(t, err, stderr.String())
		var views []decisions.Inspection
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &views))
		require.Len(t, views, 1)
		assert.Equal(t, ids[0], views[0].Decision.ID)
	})

	t.Run("JSON preserves requested order for multiple IDs", func(t *testing.T) {
		t.Parallel()
		path, ids := inspectTestDatabase(t)
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{"--output", "json", "inspect", ids[1], ids[0], "--database", path}, "test", &stdout, &stderr)
		require.NoError(t, err, stderr.String())
		var views []decisions.Inspection
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &views))
		require.Len(t, views, 2)
		assert.Equal(t, ids[1], views[0].Decision.ID)
		assert.Equal(t, ids[0], views[1].Decision.ID)
	})

	t.Run("YAML returns a sequence", func(t *testing.T) {
		t.Parallel()
		path, ids := inspectTestDatabase(t)
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{"inspect", ids[0], ids[1], "--database", path, "--output", "yaml"}, "test", &stdout, &stderr)
		require.NoError(t, err, stderr.String())
		var views []struct {
			Decision struct {
				ID string `yaml:"id"`
			} `yaml:"decision"`
		}
		require.NoError(t, yaml.Load(stdout.Bytes(), &views))
		require.Len(t, views, 2)
		assert.Equal(t, ids[0], views[0].Decision.ID)
		assert.Equal(t, ids[1], views[1].Decision.ID)
	})

	t.Run("missing ID fails without partial output", func(t *testing.T) {
		t.Parallel()
		path, ids := inspectTestDatabase(t)
		var stdout, stderr bytes.Buffer
		err := Run(t.Context(), []string{"inspect", ids[0], "missing-id", "--database", path, "--output", "json"}, "test", &stdout, &stderr)
		require.ErrorContains(t, err, "missing-id")
		assert.Empty(t, stdout.String())
	})

	t.Run("blank database flag fails parsing", func(t *testing.T) {
		t.Parallel()
		var stderr bytes.Buffer
		err := Run(t.Context(), []string{"inspect", "decision", "--database", "  "}, "test", io.Discard, &stderr)
		require.ErrorContains(t, err, "must not be blank")
	})
}
