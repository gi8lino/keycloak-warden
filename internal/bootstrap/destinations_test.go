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
			"off": {}, "ops": {Provider: config.ProviderWebhook, URL: "https://example.org", SigningSecret: "secret", Enabled: true},
		})

		require.NoError(t, err)
		assert.Equal(t, []string{"ops"}, names)
		assert.Contains(t, providers, "ops")
	})

	t.Run("enabled target requires credential", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(map[string]config.Target{
			"ops": {Enabled: true, Provider: config.ProviderWebhook, URL: "https://example.org"},
		})

		require.ErrorContains(t, err, "signing-secret")
	})

	t.Run("unknown provider is rejected", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(map[string]config.Target{
			"ops": {Enabled: true, Provider: "unknown"},
		})

		require.ErrorContains(t, err, "unknown provider")
	})
}

func TestAllowedWebhook(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"accepts HTTPS with path and query", "https://receiver.example.com/events?key=123", true},
		{"accepts local HTTP", "http://localhost:8080/events", true},
		{"accepts IPv6 loopback HTTP", "http://[::1]:8080/events", true},
		{"rejects remote HTTP", "http://receiver.example.com/events", false},
		{"rejects embedded credentials", "https://user:secret@receiver.example.com/events", false},
		{"rejects fragments", "https://receiver.example.com/events#fragment", false},
		{"rejects missing host", "https:///events", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tt.url)
			require.NoError(t, err)
			assert.Equal(t, tt.want, allowedWebhook(u))
		})
	}
	assert.False(t, allowedWebhook(nil))
}

// TestDestinationsValueResolution verifies independent credentials and resolved zone IDs.
func TestDestinationsValueResolution(t *testing.T) {
	t.Setenv("WARDEN_TEST_CF_PRIMARY_ZONE", strings.Repeat("a", 32))
	t.Setenv("WARDEN_TEST_CF_PRIMARY_TOKEN", "primary-token")
	zoneFile := filepath.Join(t.TempDir(), "zone-id")
	secretFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(zoneFile, []byte(strings.Repeat("b", 32)+"\n"), 0o600))
	require.NoError(t, os.WriteFile(secretFile, []byte(" secondary-token \n"), 0o600))

	providers, names, err := Destinations(map[string]config.Target{
		"primary": {
			Enabled: true, Provider: config.ProviderCloudflare,
			ZoneID: "env:WARDEN_TEST_CF_PRIMARY_ZONE", APIToken: "env:WARDEN_TEST_CF_PRIMARY_TOKEN",
		},
		"secondary": {
			Enabled: true, Provider: config.ProviderCloudflare,
			ZoneID: "file:" + zoneFile, APIToken: "file:" + secretFile,
		},
		"notification": {
			Enabled: true, Provider: config.ProviderWebhook,
			URL: "https://hooks.example.com/warden", SigningSecret: "literal:custom:secret",
		},
		"disabled": {
			Enabled: false, Provider: config.ProviderCloudflare,
			ZoneID: "env:WARDEN_TEST_UNDEFINED_ZONE", APIToken: "env:WARDEN_TEST_UNDEFINED_TOKEN",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"notification", "primary", "secondary"}, names)
	assert.Equal(t, "primary-token", providers["primary"].(cloudflare.Provider).Token)
	assert.Contains(t, providers["primary"].(cloudflare.Provider).RulesURL, strings.Repeat("a", 32))
	assert.Equal(t, " secondary-token ", providers["secondary"].(cloudflare.Provider).Token)
	assert.Contains(t, providers["secondary"].(cloudflare.Provider).RulesURL, strings.Repeat("b", 32))
	assert.Equal(t, "custom:secret", providers["notification"].(webhook.Provider).Secret)
}

// TestDestinationsInvalidReferences verifies strict validation and field-specific errors.
func TestDestinationsInvalidReferences(t *testing.T) {
	t.Setenv("WARDEN_TEST_EMPTY", "")
	t.Setenv("WARDEN_TEST_BLANK", " \t ")
	for _, reference := range []string{
		"", "  ", "env:WARDEN_TEST_EMPTY", "env:WARDEN_TEST_BLANK",
		"env:WARDEN_TEST_MISSING_193", "evn:WARDEN_TEST_EMPTY",
	} {
		t.Run("api-token/"+reference, func(t *testing.T) {
			_, _, err := Destinations(map[string]config.Target{
				"edge": {Enabled: true, Provider: config.ProviderCloudflare,
					ZoneID: strings.Repeat("a", 32), APIToken: reference},
			})
			require.ErrorContains(t, err, `target "edge": api-token:`)
		})
		t.Run("signing-secret/"+reference, func(t *testing.T) {
			_, _, err := Destinations(map[string]config.Target{
				"receiver": {Enabled: true, Provider: config.ProviderWebhook,
					URL: "https://example.org/events", SigningSecret: reference},
			})
			require.ErrorContains(t, err, `target "receiver": signing-secret:`)
		})
		t.Run("zone-id/"+reference, func(t *testing.T) {
			_, _, err := Destinations(map[string]config.Target{
				"edge": {Enabled: true, Provider: config.ProviderCloudflare,
					ZoneID: reference, APIToken: "literal:valid:token"},
			})
			require.ErrorContains(t, err, `target "edge": zone-id:`)
		})
	}
}

func TestDestinationsProviderValidation(t *testing.T) {
	t.Parallel()
	t.Run("invalid Cloudflare zone ID is reported before token lookup", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(map[string]config.Target{
			"edge": {Enabled: true, Provider: config.ProviderCloudflare,
				ZoneID: "invalid", APIToken: "env:WARDEN_TEST_UNDEFINED_TOKEN"},
		})
		require.ErrorContains(t, err, `zone-id: expected a 32-character hexadecimal`)
	})
	t.Run("webhook credentials remain mandatory", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(map[string]config.Target{
			"receiver": {Enabled: true, Provider: config.ProviderWebhook, URL: "https://example.org/events"},
		})
		require.ErrorContains(t, err, "signing-secret")
	})
	t.Run("rejects provider-incompatible values", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(map[string]config.Target{
			"receiver": {Enabled: true, Provider: config.ProviderWebhook,
				URL: "https://example.org/events", APIToken: "unused", SigningSecret: "valid"},
		})
		require.ErrorContains(t, err, "only valid for Cloudflare targets")
		_, _, err = Destinations(map[string]config.Target{
			"edge": {Enabled: true, Provider: config.ProviderCloudflare,
				ZoneID: strings.Repeat("a", 32), APIToken: "valid", SigningSecret: "unused"},
		})
		require.ErrorContains(t, err, "only valid for webhook targets")
	})
}
