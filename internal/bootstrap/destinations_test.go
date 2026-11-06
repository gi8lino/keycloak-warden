package bootstrap

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/config"
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
