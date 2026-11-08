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

	t.Run("strict YAML with provider-grouped targets", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `
rule:
  threshold: 2
  window: 1m
  ban: 3m
targets:
  webhook:
    ops:
      url: env:WEBHOOK_URL
      headers:
        Authorization: env:WEBHOOK_AUTHORIZATION
        X-Source: warden
  cloudflare:
    primary:
      zone-id: env:CLOUDFLARE_ZONE_ID
      api-token: env:CLOUDFLARE_API_TOKEN
`))

		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, 2, cfg.Rule.Threshold)
		assert.Equal(t, 3*time.Minute, cfg.Rule.Ban)
		assert.Equal(t, "env:WEBHOOK_URL", cfg.Targets.Webhook["ops"].URL)
		assert.Equal(t, "env:WEBHOOK_AUTHORIZATION", cfg.Targets.Webhook["ops"].Headers["Authorization"])
		assert.Equal(t, "warden", cfg.Targets.Webhook["ops"].Headers["X-Source"])
		assert.Equal(t, "env:CLOUDFLARE_ZONE_ID", cfg.Targets.Cloudflare["primary"].ZoneID)
		assert.Equal(t, "env:CLOUDFLARE_API_TOKEN", cfg.Targets.Cloudflare["primary"].APIToken)
	})

	t.Run("loaded configuration validates headers before provider construction", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, `
rule:
  threshold: 2
  window: 1m
  ban: 3m
targets:
  webhook:
    ops:
      url: https://example.org
      headers:
        CONTENT-TYPE: text/plain
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(), "Content-Type is reserved")
	})

	t.Run("rejects old flat target format", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "targets:\n  edge:\n    provider: cloudflare\n    zone-id: example\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects provider fields inside webhook", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "targets:\n  webhook:\n    ops:\n      url: https://example.org\n      provider: webhook\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects signing secret field", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "targets:\n  webhook:\n    ops:\n      url: https://example.org\n      signing-secret: old\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects unknown provider group", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "targets:\n  other:\n    edge:\n      url: https://example.org\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects unknown fields", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "typo: invalid\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects duplicate keys", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "rule: {}\nrule: {}\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects duplicate nested keys", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "targets:\n  webhook:\n    ops:\n      headers:\n        X-Key: a\n        X-Key: b\n"))
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
