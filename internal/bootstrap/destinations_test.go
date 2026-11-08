package bootstrap

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/providers/cloudflare"
	"github.com/gi8lino/keycloak-warden/internal/providers/webhook"
)

func TestDestinations(t *testing.T) {
	t.Parallel()

	t.Run("only explicitly enabled targets receive decisions", func(t *testing.T) {
		t.Parallel()

		providers, names, err := Destinations(map[string]config.Target{
			"off": {}, "ops": {Provider: config.ProviderWebhook, URL: "https://example.org", Secret: "secret", Enabled: true},
		})

		require.NoError(t, err)
		assert.Equal(t, []string{"ops"}, names)
		assert.Contains(t, providers, "ops")
	})

	t.Run("enabled target requires credential", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(map[string]config.Target{"ops": {Enabled: true}})

		require.ErrorContains(t, err, "credential")
	})
}

func TestAllowedWebhook(t *testing.T) {
	t.Parallel()

	t.Run("accepts HTTPS with path and query", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("https://receiver.example.com/events?key=123")

		require.NoError(t, err)
		assert.True(t, allowedWebhook(u))
	})

	t.Run("accepts local HTTP", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("http://localhost:8080/events")

		require.NoError(t, err)
		assert.True(t, allowedWebhook(u))
	})

	t.Run("accepts IPv6 loopback HTTP", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("http://[::1]:8080/events")

		require.NoError(t, err)
		assert.True(t, allowedWebhook(u))
	})

	t.Run("rejects remote HTTP", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("http://receiver.example.com/events")

		require.NoError(t, err)
		assert.False(t, allowedWebhook(u))
	})

	t.Run("rejects embedded credentials", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("https://user:secret@receiver.example.com/events")

		require.NoError(t, err)
		assert.False(t, allowedWebhook(u))
	})

	t.Run("rejects fragments", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("https://receiver.example.com/events#fragment")

		require.NoError(t, err)
		assert.False(t, allowedWebhook(u))
	})

	t.Run("rejects missing host", func(t *testing.T) {
		t.Parallel()

		u, err := url.Parse("https:///events")

		require.NoError(t, err)
		assert.False(t, allowedWebhook(u))
	})

	t.Run("rejects nil URL", func(t *testing.T) {
		t.Parallel()

		assert.False(t, allowedWebhook(nil))
	})
}

// TestDestinationsSecretResolution verifies independent credentials and strict references.
func TestDestinationsSecretResolution(t *testing.T) {
	t.Setenv("WARDEN_TEST_CF_PRIMARY", "primary-token")
	t.Setenv("WARDEN_TEST_BLANK", "   ")
	file := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(file, []byte(" secondary-token \n"), 0600))

	providers, names, err := Destinations(map[string]config.Target{
		"primary": {
			Enabled: true, Provider: config.ProviderCloudflare,
			ZoneID: strings.Repeat("a", 32), Secret: "env:WARDEN_TEST_CF_PRIMARY",
		},
		"secondary": {
			Enabled: true, Provider: config.ProviderCloudflare,
			ZoneID: strings.Repeat("b", 32), Secret: "file:" + file,
		},
		"notification": {
			Enabled: true, Provider: config.ProviderWebhook,
			URL: "https://hooks.example.com/warden", Secret: "literal:custom:secret",
		},
		"disabled": {
			Enabled: false, Provider: config.ProviderCloudflare,
			Secret: "env:WARDEN_TEST_UNDEFINED",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"notification", "primary", "secondary"}, names)
	assert.Equal(t, "primary-token", providers["primary"].(cloudflare.Provider).Token)
	assert.Equal(t, " secondary-token ", providers["secondary"].(cloudflare.Provider).Token)
	assert.Equal(t, "custom:secret", providers["notification"].(webhook.Provider).Secret)
}

// TestDestinationsBadSecretReferences checks fail-fast errors for enabled targets.
func TestDestinationsBadSecretReferences(t *testing.T) {
	t.Setenv("WARDEN_TEST_EMPTY", "")
	t.Setenv("WARDEN_TEST_BLANK", " 	 ")
	for _, secret := range []string{
		"", "  ", "env:WARDEN_TEST_EMPTY", "env:WARDEN_TEST_BLANK",
		"env:WARDEN_TEST_MISSING_193", "evn:WARDEN_TEST_EMPTY",
	} {
		t.Run(secret, func(t *testing.T) {
			_, _, err := Destinations(map[string]config.Target{
				"edge": {
					Enabled: true, Provider: config.ProviderCloudflare,
					ZoneID: strings.Repeat("a", 32), Secret: secret,
				},
			})
			require.ErrorContains(t, err, `target "edge": resolve destination credential`)
		})
	}
}
