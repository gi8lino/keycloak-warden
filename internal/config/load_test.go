package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConfig stores one test configuration in a temporary YAML file.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")

	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("strict YAML with typed providers", func(t *testing.T) {
		t.Parallel()

		path := writeConfig(t, `
rule:
  threshold: 2
  window: 1m
  ban: 3m
targets:
  ops:
    provider: webhook
    enabled: true
    url: https://example.org/events
    signing-secret: outbound
`)
		cfg, err := Load(path)

		require.NoError(t, err)
		assert.Equal(t, 2, cfg.Rule.Threshold)
		assert.Equal(t, 3*time.Minute, cfg.Rule.Ban)
		assert.Equal(t, ProviderWebhook, cfg.Targets["ops"].Provider)
		assert.Equal(t, "outbound", cfg.Targets["ops"].SigningSecret)
	})

	t.Run("cloudflare target retains resolvable configuration", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `
rule:
  threshold: 5
  window: 1m
  ban: 15m
targets:
  edge:
    enabled: true
    provider: cloudflare
    zone-id: env:CLOUDFLARE_ZONE_ID
    api-token: env:CLOUDFLARE_API_TOKEN
`))
		require.NoError(t, err)
		assert.Equal(t, ProviderCloudflare, cfg.Targets["edge"].Provider)
		assert.Equal(t, "env:CLOUDFLARE_ZONE_ID", cfg.Targets["edge"].ZoneID)
		assert.Equal(t, "env:CLOUDFLARE_API_TOKEN", cfg.Targets["edge"].APIToken)
	})

	t.Run("rejects legacy generic secret field", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "targets:\n  edge:\n    provider: cloudflare\n    secret: legacy-token\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects unknown fields", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "typo: invalid\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects unknown provider", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "targets:\n  edge:\n    provider: other\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects duplicate keys", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "rule: {}\nrule: {}\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects duplicate nested keys", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "targets:\n  ops:\n    enabled: true\n    enabled: false\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects multiple documents", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "rule: {}\n---\nrule: {}\n"))

		require.ErrorContains(t, err, "expected one YAML document")
	})

	t.Run("rejects invalid duration", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "rule:\n  window: not-a-duration\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects listener in YAML", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "listen-address: ':8081'\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects management listener in YAML", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "management-listen-address: ':8082'\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects database in YAML", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "database: secret.db\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects incoming secret in YAML", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "snitch-secret: shared\n"))

		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("does not silently default detection rule", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, "targets: {}\n"))

		require.NoError(t, err)
		assert.Zero(t, cfg.Rule.Threshold)
		require.ErrorContains(t, cfg.Rule.Validate(), "threshold")
	})

	t.Run("rejects missing file", func(t *testing.T) {
		t.Parallel()

		_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))

		require.Error(t, err)
	})
}
