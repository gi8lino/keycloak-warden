package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

func TestNotificationsValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts multiple named destinations", func(t *testing.T) {
		t.Parallel()

		cfg := Notifications{
			Delivery: Delivery{
				Webhook: map[string]WebhookTarget{
					"slack-security":         {URL: "https://example.org/security"},
					"slack-operations":       {URL: "https://example.org/operations"},
					"msteams-administrators": {URL: "https://example.org/teams"},
				},
			},
		}
		rules := detection.Rules{"audit": {Actions: detection.Actions{Notify: []string{"slack-security", "slack-operations", "msteams-administrators"}}}}
		assert.NoError(t, cfg.Validate(rules))
	})

	t.Run("rejects unknown destination", func(t *testing.T) {
		t.Parallel()

		rules := detection.Rules{"audit": {Actions: detection.Actions{Notify: []string{"missing"}}}}
		assert.ErrorContains(t, (Notifications{}).Validate(rules), "unknown notification destination")
	})

	t.Run("rejects duplicate destination references", func(t *testing.T) {
		t.Parallel()

		cfg := Notifications{
			Delivery: Delivery{
				Webhook: map[string]WebhookTarget{"slack-ops": {URL: "https://example.org"}},
			},
		}
		rules := detection.Rules{"audit": {Actions: detection.Actions{Notify: []string{"slack-ops", "slack-ops"}}}}
		assert.ErrorContains(t, cfg.Validate(rules), "duplicate notification destination")
	})

	t.Run("rejects invalid retry bounds", func(t *testing.T) {
		t.Parallel()

		cfg := Notifications{
			Delivery: Delivery{
				RetryInitialDelay: time.Minute,
				RetryMaxDelay:     time.Second,
			},
		}
		assert.ErrorContains(t, cfg.Validate(nil), "retry-max-delay")
	})

	t.Run("loads named webhooks and rule references from YAML", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeConfig(t, `rules:
  audit:
    selector:
      kind: admin
    aggregation:
      group-by: realm
      threshold: 1
      window: 1m
    actions:
      notify: [slack-ops, msteams-admin]
notifications:
  retry-initial-delay: 2s
  webhook:
    slack-ops:
      url: https://example.org/slack
    msteams-admin:
      url: https://example.org/teams
`))
		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []string{"slack-ops", "msteams-admin"}, cfg.Rules["audit"].Actions.Notify)
		assert.Equal(t, 2*time.Second, cfg.Notifications.RetryPolicy().InitialDelay)
	})

	t.Run("rejects provider-specific notification groups", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "notifications:\n  slack: {}\n"))
		assert.Error(t, err)
	})

	t.Run("rejects old provider-qualified references", func(t *testing.T) {
		t.Parallel()

		cfg := Notifications{
			Delivery: Delivery{
				Webhook: map[string]WebhookTarget{"ops": {URL: "https://example.org"}},
			},
		}
		rules := detection.Rules{"audit": {Actions: detection.Actions{Notify: []string{"webhook.ops"}}}}
		assert.ErrorContains(t, cfg.Validate(rules), "unknown notification destination")
	})

	t.Run("rejects the old targets key", func(t *testing.T) {
		t.Parallel()

		_, err := Load(writeConfig(t, "targets: {}\n"))
		assert.Error(t, err)
	})
}
