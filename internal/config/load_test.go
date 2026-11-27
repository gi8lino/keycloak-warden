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
      ban: 3m
enforcements:
  webhook:
    ops:
      url: env:WEBHOOK_URL
      body-template: file:/config/slack.tmpl
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
		assert.Equal(t, 2, cfg.Rules["brute-force"].Aggregation.Threshold)
		assert.Equal(t, 3*time.Minute, cfg.Rules["brute-force"].Actions.Ban)
		assert.Equal(t, "env:WEBHOOK_URL", cfg.Enforcements.Webhook["ops"].URL)
		assert.Equal(t, "file:/config/slack.tmpl", cfg.Enforcements.Webhook["ops"].BodyTemplate)
		assert.Equal(t, "env:WEBHOOK_AUTHORIZATION", cfg.Enforcements.Webhook["ops"].Headers["Authorization"])
		assert.Equal(t, "warden", cfg.Enforcements.Webhook["ops"].Headers["X-Source"])
		assert.Equal(t, "env:CLOUDFLARE_ZONE_ID", cfg.Enforcements.Cloudflare["primary"].ZoneID)
		assert.Equal(t, "env:CLOUDFLARE_API_TOKEN", cfg.Enforcements.Cloudflare["primary"].APIToken)
	})

	t.Run("accepts a quoted rule name with punctuation", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `
rules:
  "Auth/Login.Errors":
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 2
      window: 1m
`))

		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, "Auth/Login.Errors", cfg.Rules.Ordered()[0].Name)
	})

	t.Run("rejects a quoted rule name with whitespace during validation", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `
rules:
  "login errors":
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 2
      window: 1m
`))

		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(), "rule name")
	})

	t.Run("loaded configuration validates headers before provider construction", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `
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
      ban: 3m
enforcements:
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

		_, err := Load(writeConfig(t, "enforcements:\n  edge:\n    provider: cloudflare\n    zone-id: example\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects provider fields inside webhook", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "enforcements:\n  webhook:\n    ops:\n      url: https://example.org\n      provider: webhook\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects signing secret field", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "enforcements:\n  webhook:\n    ops:\n      url: https://example.org\n      signing-secret: old\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects unknown provider group", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "enforcements:\n  other:\n    edge:\n      url: https://example.org\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects unknown fields", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "typo: invalid\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects duplicate keys", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "rules: {}\nrules: {}\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects duplicate nested keys", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "enforcements:\n  webhook:\n    ops:\n      headers:\n        X-Key: a\n        X-Key: b\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects multiple documents", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "rules: {}\n---\nrules: {}\n"))
		require.ErrorContains(t, err, "expected one YAML document")
	})

	t.Run("rejects invalid duration", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "rules:\n  brute-force:\n    selector:\n      kind: user\n      events: [LOGIN_ERROR]\n    aggregation:\n      group-by: ip\n      threshold: 2\n      window: not-a-duration\n    actions:\n      ban: 15m\n"))
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

		cfg, err := Load(writeConfig(t, "enforcements: {}\n"))
		require.NoError(t, err)
		assert.Empty(t, cfg.Rules)
		require.ErrorContains(t, cfg.Validate(), "configure between one and 64 rules")
	})

	t.Run("rejects missing file", func(t *testing.T) {
		t.Parallel()

		_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
		require.Error(t, err)
	})
}

func TestAttemptLimits(t *testing.T) {
	t.Parallel()
	t.Run("inherits and overrides the YAML budget by named destination", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, `
enforcements:
  max-attempts: 4
  webhook:
    receiver:
      url: https://example.org
    slack:
      url: https://example.org/slack
      max-attempts: 2
  cloudflare:
    edge:
      api-token: example
      zone-id: example
      max-attempts: 1
`))
		require.NoError(t, err)
		require.NoError(t, cfg.Enforcements.Validate())
		require.NotNil(t, cfg.Enforcements.MaxAttempts)
		assert.Equal(t, 4, *cfg.Enforcements.MaxAttempts)
		assert.Nil(t, cfg.Enforcements.Webhook["receiver"].MaxAttempts)
		require.NotNil(t, cfg.Enforcements.Webhook["slack"].MaxAttempts)
		assert.Equal(t, 2, *cfg.Enforcements.Webhook["slack"].MaxAttempts)
		require.NotNil(t, cfg.Enforcements.Cloudflare["edge"].MaxAttempts)
		assert.Equal(t, 1, *cfg.Enforcements.Cloudflare["edge"].MaxAttempts)
	})
	t.Run("rejects an explicit zero", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, "enforcements:\n  max-attempts: 0\n  webhook:\n    receiver:\n      url: https://example.org\n"))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Enforcements.Validate(), "max-attempts")
	})
}

func TestAdmissionConfiguration(t *testing.T) {
	t.Parallel()

	t.Run("accepts protection without targets", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, `protected-ips:
  - 203.0.113.0/24
  - 2001:db8::1
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
      ban: 15m
`))
		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []string{"203.0.113.0/24", "2001:db8::1"}, cfg.ProtectedIPs)
	})

	t.Run("rejects observe-only as a YAML setting", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "observe-only: true\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("invalid protection fails startup", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, `protected-ips: [bad-address]
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
      ban: 15m
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(), "invalid protected IP or CIDR")
	})
}

func TestLoadNamedRules(t *testing.T) {
	t.Parallel()

	t.Run("loads independent named rules and longest observation window", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, `
rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 5
      window: 1m
    actions:
      ban: 15m
  role-changes:
    selector:
      kind: admin
      resources: [REALM_ROLE_MAPPING]
      operations: [CREATE]
      success-only: true
    aggregation:
      group-by: realm
      threshold: 1
      window: 2m
`))
		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
		require.Len(t, cfg.Rules, 2)
		assert.Contains(t, cfg.Rules, "brute-force")
		assert.Equal(t, 2*time.Minute, cfg.ObservationWindow())
	})

	t.Run("rejects singular rule configuration", func(t *testing.T) {
		t.Parallel()
		_, err := Load(writeConfig(t, "rule: {}\n"))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("rejects a ban outside actions", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, `rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 2
      window: 1m
    ban: 15m
`))
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("accepts missing actions for monitoring", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 2
      window: 1m
`))
		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
		assert.False(t, cfg.Rules.RequiresEnforcement())
	})

	t.Run("rejects an explicitly empty rules map", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load(writeConfig(t, "rules: {}\n"))
		require.NoError(t, err)
		require.Error(t, cfg.Validate())
	})
}
