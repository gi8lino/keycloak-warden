package bootstrap

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/providers/webhook"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestNotifications(t *testing.T) {
	t.Parallel()

	t.Run("shares webhook settings and routing identity with enforcement", func(t *testing.T) {
		t.Parallel()

		settings := config.WebhookTarget{
			URL:          "https://example.org/hook",
			Headers:      map[string]string{"X-Source": "warden"},
			BodyTemplate: `literal:{"id": {{ .Payload.ID | json }}, "channel": {{ .Vars.channel | json }}}`,
			TemplateVars: map[string]string{"channel": "example"},
		}
		notificationTargets, err := Notifications(config.Notifications{
			Delivery: config.Delivery{
				Webhook: map[string]config.WebhookTarget{"ops": settings},
			},
		})
		require.NoError(t, err)
		enforcementTargets, _, err := Destinations(config.Enforcements{
			Delivery: config.Delivery{
				Webhook: map[string]config.WebhookTarget{"ops": settings},
			},
		})
		require.NoError(t, err)

		notification := notificationTargets["ops"]
		enforcement := enforcementTargets["webhook.ops"]
		assert.IsType(t, webhook.Provider[model.Incident]{}, notification.Provider)
		assert.IsType(t, webhook.Provider[model.Decision]{}, enforcement.Provider)
		assert.Equal(t, enforcement.Identity, notification.Identity)
		assert.Equal(t, enforcement.MaxAttempts, notification.MaxAttempts)
	})

	t.Run("rejects a decision-only template for an incident", func(t *testing.T) {
		t.Parallel()

		_, err := Notifications(config.Notifications{
			Delivery: config.Delivery{
				Webhook: map[string]config.WebhookTarget{
					"ops": {
						URL:          "https://example.org/hook",
						BodyTemplate: `literal:{"state": {{ .Payload.State | json }}}`,
					},
				},
			},
		})
		require.ErrorContains(t, err, "body-template")
	})
}

func TestDeploymentTemplates(t *testing.T) {
	t.Parallel()

	t.Run("ban Slack API", func(t *testing.T) {
		t.Parallel()
		assertBanTemplate(t, "ban-slack-api.json.tmpl", nil)
	})
	t.Run("ban Slack bot", func(t *testing.T) {
		t.Parallel()
		assertBanTemplate(t, "ban-slack-bot.json.tmpl", map[string]string{"channel": "C123"})
	})
	t.Run("ban Teams", func(t *testing.T) {
		t.Parallel()
		assertBanTemplate(t, "ban-msteams.json.tmpl", nil)
	})
	t.Run("incident Slack API", func(t *testing.T) {
		t.Parallel()
		assertIncidentTemplate(t, "incident-slack-api.json.tmpl", nil)
	})
	t.Run("incident Slack bot", func(t *testing.T) {
		t.Parallel()
		assertIncidentTemplate(t, "incident-slack-bot.json.tmpl", map[string]string{"channel": "C123"})
	})
	t.Run("incident Teams", func(t *testing.T) {
		t.Parallel()
		assertIncidentTemplate(t, "incident-msteams.json.tmpl", nil)
	})
}

// assertBanTemplate validates the supplied template against both decision states.
func assertBanTemplate(t *testing.T, name string, vars map[string]string) {
	t.Helper()

	_, _, err := Destinations(config.Enforcements{
		Delivery: config.Delivery{
			Webhook: map[string]config.WebhookTarget{
				"example": {
					URL:          "https://example.org/hook",
					BodyTemplate: "file:" + filepath.Join("..", "..", "deploy", "kubernetes", "templates", name),
					TemplateVars: vars,
				},
			},
		},
	})
	require.NoError(t, err)
}

// assertIncidentTemplate validates the supplied template against representative incidents.
func assertIncidentTemplate(t *testing.T, name string, vars map[string]string) {
	t.Helper()

	_, err := Notifications(config.Notifications{
		Delivery: config.Delivery{
			Webhook: map[string]config.WebhookTarget{
				"example": {
					URL:          "https://example.org/hook",
					BodyTemplate: "file:" + filepath.Join("..", "..", "deploy", "kubernetes", "templates", name),
					TemplateVars: vars,
				},
			},
		},
	})
	require.NoError(t, err)
}
