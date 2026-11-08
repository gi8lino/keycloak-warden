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

	t.Run("groups use stable provider-qualified names", func(t *testing.T) {
		t.Parallel()
		providers, names, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"edge": {URL: "https://example.org/a"},
				"ops":  {URL: "https://example.org/b"},
			},
			Cloudflare: map[string]config.CloudflareTarget{
				"edge": {ZoneID: strings.Repeat("a", 32), APIToken: "token"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"cloudflare.edge", "webhook.edge", "webhook.ops"}, names)
		assert.IsType(t, webhook.Provider{}, providers["webhook.edge"])
		assert.IsType(t, cloudflare.Provider{}, providers["cloudflare.edge"])
	})

	t.Run("supports custom names and dot-separated identifiers", func(t *testing.T) {
		t.Parallel()
		providers, names, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"custom-name-a": {URL: "https://example.org/a"},
				"custom-name-b": {URL: "https://example.org/b"},
			},
			Cloudflare: map[string]config.CloudflareTarget{
				"primary-domain": {ZoneID: strings.Repeat("a", 32), APIToken: "token"},
				"backup-domain":  {ZoneID: strings.Repeat("b", 32), APIToken: "token"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{
			"cloudflare.backup-domain", "cloudflare.primary-domain",
			"webhook.custom-name-a", "webhook.custom-name-b",
		}, names)
		assert.IsType(t, webhook.Provider{}, providers["webhook.custom-name-a"])
		assert.IsType(t, cloudflare.Provider{}, providers["cloudflare.primary-domain"])
	})

	t.Run("rejects invalid target names", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"", "  ", " padded", "foo bar", "foo\nbar", "foo/bar"} {
			_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{name: {URL: "https://example.org"}}})
			require.ErrorContains(t, err, "name")
		}
	})
}

func TestResolveWebhookURL(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "literal HTTPS", value: "https://example.org/events?key=a:b", want: "https://example.org/events?key=a:b"},
		{name: "literal loopback HTTP", value: "http://127.0.0.1:8090/header", want: "http://127.0.0.1:8090/header"},
		{name: "explicit literal", value: "literal:https://example.org/events", want: "https://example.org/events"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			providers, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
				"edge": {URL: tt.value},
			}})
			require.NoError(t, err)
			assert.Equal(t, tt.want, providers["webhook.edge"].(webhook.Provider).URL)
		})
	}
	t.Run("unknown URL reference scheme remains invalid", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"edge": {URL: "htps://example.org/events"},
		}})
		require.ErrorContains(t, err, `url: resolve value:`)
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

// TestDestinationsValueResolution verifies resolved URLs, headers, and Cloudflare values.
func TestDestinationsValueResolution(t *testing.T) {
	t.Setenv("WARDEN_TEST_CF_PRIMARY_ZONE", strings.Repeat("a", 32))
	t.Setenv("WARDEN_TEST_CF_PRIMARY_TOKEN", "primary-token")
	t.Setenv("WARDEN_TEST_WEBHOOK_URL", "https://hooks.example.com/warden")
	t.Setenv("WARDEN_TEST_WEBHOOK_HEADER", "Bearer secret")
	zoneFile := filepath.Join(t.TempDir(), "zone-id")
	secretFile := filepath.Join(t.TempDir(), "token")
	headerFile := filepath.Join(t.TempDir(), "header")
	require.NoError(t, os.WriteFile(zoneFile, []byte(strings.Repeat("b", 32)+"\n"), 0o600))
	require.NoError(t, os.WriteFile(secretFile, []byte(" secondary-token \n"), 0o600))
	require.NoError(t, os.WriteFile(headerFile, []byte("file-header-value\n"), 0o600))

	providers, names, err := Destinations(config.Targets{
		Cloudflare: map[string]config.CloudflareTarget{
			"primary":   {ZoneID: "env:WARDEN_TEST_CF_PRIMARY_ZONE", APIToken: "env:WARDEN_TEST_CF_PRIMARY_TOKEN"},
			"secondary": {ZoneID: "file:" + zoneFile, APIToken: "file:" + secretFile},
		},
		Webhook: map[string]config.WebhookTarget{
			"notification": {
				URL: "env:WARDEN_TEST_WEBHOOK_URL",
				Headers: map[string]string{
					"Authorization": "env:WARDEN_TEST_WEBHOOK_HEADER",
					"X-API-Key":     "file:" + headerFile,
					"X-Source":      "literal:custom:source",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"cloudflare.primary", "cloudflare.secondary", "webhook.notification"}, names)
	assert.Equal(t, "primary-token", providers["cloudflare.primary"].(cloudflare.Provider).Token)
	assert.Contains(t, providers["cloudflare.primary"].(cloudflare.Provider).RulesURL, strings.Repeat("a", 32))
	assert.Equal(t, " secondary-token ", providers["cloudflare.secondary"].(cloudflare.Provider).Token)
	assert.Contains(t, providers["cloudflare.secondary"].(cloudflare.Provider).RulesURL, strings.Repeat("b", 32))
	p := providers["webhook.notification"].(webhook.Provider)
	assert.Equal(t, "https://hooks.example.com/warden", p.URL)
	assert.Equal(t, "Bearer secret", p.Headers.Get("Authorization"))
	assert.Equal(t, "file-header-value", p.Headers.Get("X-API-Key"))
	assert.Equal(t, "custom:source", p.Headers.Get("X-Source"))

	// Resolved values are snapshots, not dynamically looked up on delivery.
	t.Setenv("WARDEN_TEST_WEBHOOK_HEADER", "different")
	assert.Equal(t, "Bearer secret", p.Headers.Get("Authorization"))
}

// TestDestinationsInvalidReferences verifies field-specific errors for every resolvable setting.
func TestDestinationsInvalidReferences(t *testing.T) {
	t.Setenv("WARDEN_TEST_EMPTY", "")
	t.Setenv("WARDEN_TEST_BLANK", " \t ")
	for _, reference := range []string{
		"", "  ", "env:WARDEN_TEST_EMPTY", "env:WARDEN_TEST_BLANK",
		"env:WARDEN_TEST_MISSING_193", "evn:WARDEN_TEST_EMPTY",
	} {
		t.Run("api-token/"+reference, func(t *testing.T) {
			_, _, err := Destinations(config.Targets{Cloudflare: map[string]config.CloudflareTarget{
				"edge": {ZoneID: strings.Repeat("a", 32), APIToken: reference},
			}})
			require.ErrorContains(t, err, `target "cloudflare.edge": api-token:`)
		})
		t.Run("url/"+reference, func(t *testing.T) {
			_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
				"receiver": {URL: reference},
			}})
			require.ErrorContains(t, err, `target "webhook.receiver": url:`)
		})
		t.Run("header/"+reference, func(t *testing.T) {
			_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
				"receiver": {URL: "https://example.org/events", Headers: map[string]string{"X-API-Key": reference}},
			}})
			require.ErrorContains(t, err, `headers X-API-Key:`)
		})
		t.Run("zone-id/"+reference, func(t *testing.T) {
			_, _, err := Destinations(config.Targets{Cloudflare: map[string]config.CloudflareTarget{
				"edge": {ZoneID: reference, APIToken: "literal:valid:token"},
			}})
			require.ErrorContains(t, err, `target "cloudflare.edge": zone-id:`)
		})
	}
}

func TestDestinationsProviderValidation(t *testing.T) {
	t.Parallel()
	t.Run("invalid Cloudflare zone ID is reported before token lookup", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(config.Targets{Cloudflare: map[string]config.CloudflareTarget{
			"edge": {ZoneID: "invalid", APIToken: "env:WARDEN_TEST_UNDEFINED_TOKEN"},
		}})
		require.ErrorContains(t, err, "zone-id: expected a 32-character hexadecimal")
	})
	t.Run("webhook URL must use an allowed transport", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"receiver": {URL: "http://remote.example/events"},
		}})
		require.ErrorContains(t, err, "url: expected HTTPS")
	})
}

func TestWebhookHeaderValueValidation(t *testing.T) {
	for _, value := range []string{"evil\r\nX-Test: yes", "\x00bad", "bad\x7f"} {
		t.Run("value/"+value, func(t *testing.T) {
			t.Parallel()
			_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
				"edge": {URL: "https://example.org", Headers: map[string]string{"X-API-Key": value}},
			}})
			require.ErrorContains(t, err, "invalid HTTP header value")
		})
	}
	t.Run("allows transport-related headers other than Content-Type", func(t *testing.T) {
		t.Parallel()
		providers, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"edge": {URL: "https://example.org", Headers: map[string]string{
				"Host": "example.org", "Content-Length": "123", "Transfer-Encoding": "chunked",
			}},
		}})
		require.NoError(t, err)
		p := providers["webhook.edge"].(webhook.Provider)
		assert.Equal(t, "example.org", p.Headers.Get("Host"))
		assert.Equal(t, "123", p.Headers.Get("Content-Length"))
		assert.Equal(t, "chunked", p.Headers.Get("Transfer-Encoding"))
	})
	t.Run("accepts tabs in resolved header values", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"edge": {URL: "https://example.org", Headers: map[string]string{"X-Key": "abc\tdef"}},
		}})
		require.NoError(t, err)
	})
	t.Run("validates resolved header value", func(t *testing.T) {
		t.Setenv("WARDEN_TEST_BAD_HEADER_VALUE", "oops\r\nInjected: yes")
		_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"edge": {URL: "https://example.org", Headers: map[string]string{"X-Key": "env:WARDEN_TEST_BAD_HEADER_VALUE"}},
		}})
		require.ErrorContains(t, err, "invalid HTTP header value")
	})
	t.Run("direct initialization rejects malformed struct configuration", func(t *testing.T) {
		t.Parallel()
		_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"edge": {URL: "https://example.org", Headers: map[string]string{"Content-Type": "text/plain"}},
		}})
		require.ErrorContains(t, err, "Content-Type is reserved")
	})
}
