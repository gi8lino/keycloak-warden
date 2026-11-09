package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/config"
)

func TestDeterministicDestinations(t *testing.T) {
	t.Parallel()

	t.Run("rejects an empty target configuration", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(config.Targets{})
		require.ErrorContains(t, err, "at least one")
	})

	t.Run("reports the alphabetically first invalid destination", func(t *testing.T) {
		t.Parallel()
		targets := config.Targets{Webhook: map[string]config.WebhookTarget{
			"zeta":  {URL: "bad://example.org"},
			"alpha": {URL: "https://example.org", Headers: map[string]string{"X-Key": "env:WARDEN_TEST_UNKNOWN_ALPHA_201"}},
		}}
		_, _, err := Destinations(targets)
		require.ErrorContains(t, err, `target "webhook.alpha"`)
	})

	t.Run("reports the alphabetically first invalid header", func(t *testing.T) {
		t.Parallel()
		targets := config.Targets{Webhook: map[string]config.WebhookTarget{
			"ops": {URL: "https://example.org", Headers: map[string]string{
				"Z-Key": "env:WARDEN_TEST_UNKNOWN_Z_202",
				"A-Key": "env:WARDEN_TEST_UNKNOWN_A_203",
			}},
		}}
		_, _, err := Destinations(targets)
		require.ErrorContains(t, err, "headers A-Key:")
	})
}
