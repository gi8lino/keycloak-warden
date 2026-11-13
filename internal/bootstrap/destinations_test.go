package bootstrap

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
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

	t.Run("rejects empty webhook target name", func(t *testing.T) {
		t.Parallel()

		assertInvalidWebhookTargetName(t, "")
	})

	t.Run("rejects whitespace-only webhook target name", func(t *testing.T) {
		t.Parallel()

		assertInvalidWebhookTargetName(t, "  ")
	})

	t.Run("rejects padded webhook target name", func(t *testing.T) {
		t.Parallel()

		assertInvalidWebhookTargetName(t, " padded")
	})

	t.Run("rejects webhook target name containing spaces", func(t *testing.T) {
		t.Parallel()

		assertInvalidWebhookTargetName(t, "foo bar")
	})

	t.Run("rejects webhook target name containing a newline", func(t *testing.T) {
		t.Parallel()

		assertInvalidWebhookTargetName(t, "foo\nbar")
	})

	t.Run("accepts slashes in webhook target names", func(t *testing.T) {
		t.Parallel()

		providers, names, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"ops/alerts": {URL: "https://example.org/events"},
		}})
		require.NoError(t, err)
		assert.Equal(t, []string{"webhook.ops/alerts"}, names)
		assert.IsType(t, webhook.Provider{}, providers["webhook.ops/alerts"])
	})

	t.Run("accepts slashes in cloudflare target names", func(t *testing.T) {
		t.Parallel()

		providers, names, err := Destinations(config.Targets{Cloudflare: map[string]config.CloudflareTarget{
			"primary/zone": {ZoneID: strings.Repeat("a", 32), APIToken: "token"},
		}})
		require.NoError(t, err)
		assert.Equal(t, []string{"cloudflare.primary/zone"}, names)
		assert.IsType(t, cloudflare.Provider{}, providers["cloudflare.primary/zone"])
	})
}

// assertInvalidWebhookTargetName checks that invalid destination identifiers fail validation.
func assertInvalidWebhookTargetName(t *testing.T, name string) {
	t.Helper()
	_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
		name: {URL: "https://example.org"},
	}})
	require.ErrorContains(t, err, "name")
}

func TestResolveWebhookURL(t *testing.T) {
	t.Parallel()

	t.Run("accepts literal HTTPS URL", func(t *testing.T) {
		t.Parallel()

		assertResolvedWebhookURL(t, "https://example.org/events?key=a:b", "https://example.org/events?key=a:b")
	})

	t.Run("accepts literal loopback HTTP URL", func(t *testing.T) {
		t.Parallel()

		assertResolvedWebhookURL(t, "http://127.0.0.1:8090/header", "http://127.0.0.1:8090/header")
	})

	t.Run("accepts explicit literal reference", func(t *testing.T) {
		t.Parallel()

		assertResolvedWebhookURL(t, "literal:https://example.org/events", "https://example.org/events")
	})

	t.Run("rejects unknown URL reference scheme", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
			"edge": {URL: "htps://example.org/events"},
		}})
		require.ErrorContains(t, err, `url: resolver: not found`)
	})
}

// assertResolvedWebhookURL checks the effective URL of a constructed webhook provider.
func assertResolvedWebhookURL(t *testing.T, reference, want string) {
	t.Helper()
	providers, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
		"edge": {URL: reference},
	}})
	require.NoError(t, err)
	assert.Equal(t, want, providers["webhook.edge"].(webhook.Provider).URL)
}

func TestAllowedWebhook(t *testing.T) {
	t.Parallel()

	t.Run("accepts HTTPS with path and query", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "https://receiver.example.com/events?key=123", true)
	})

	t.Run("accepts local HTTP", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "http://localhost:8080/events", true)
	})

	t.Run("accepts IPv6 loopback HTTP", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "http://[::1]:8080/events", true)
	})

	t.Run("rejects remote HTTP", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "http://receiver.example.com/events", false)
	})

	t.Run("rejects embedded credentials", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "https://user:secret@receiver.example.com/events", false)
	})

	t.Run("rejects fragments", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "https://receiver.example.com/events#fragment", false)
	})

	t.Run("rejects missing host", func(t *testing.T) {
		t.Parallel()

		assertAllowedWebhook(t, "https:///events", false)
	})

	t.Run("rejects nil URL", func(t *testing.T) {
		t.Parallel()

		assert.False(t, allowedWebhook(nil))
	})
}

// assertAllowedWebhook parses a URL and checks its transport policy decision.
func assertAllowedWebhook(t *testing.T, rawURL string, want bool) {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	assert.Equal(t, want, allowedWebhook(u))
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

	t.Run("rejects empty API token", func(t *testing.T) {
		assertInvalidAPIToken(t, "")
	})

	t.Run("rejects empty webhook URL", func(t *testing.T) {
		assertInvalidWebhookURL(t, "")
	})

	t.Run("rejects empty webhook header", func(t *testing.T) {
		assertInvalidWebhookHeader(t, "")
	})

	t.Run("rejects empty zone ID", func(t *testing.T) {
		assertInvalidZoneID(t, "")
	})

	t.Run("rejects blank API token", func(t *testing.T) {
		assertInvalidAPIToken(t, "  ")
	})

	t.Run("rejects blank webhook URL", func(t *testing.T) {
		assertInvalidWebhookURL(t, "  ")
	})

	t.Run("rejects blank webhook header", func(t *testing.T) {
		assertInvalidWebhookHeader(t, "  ")
	})

	t.Run("rejects blank zone ID", func(t *testing.T) {
		assertInvalidZoneID(t, "  ")
	})

	t.Run("rejects empty environment variable API token", func(t *testing.T) {
		assertInvalidAPIToken(t, "env:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects empty environment variable webhook URL", func(t *testing.T) {
		assertInvalidWebhookURL(t, "env:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects empty environment variable webhook header", func(t *testing.T) {
		assertInvalidWebhookHeader(t, "env:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects empty environment variable zone ID", func(t *testing.T) {
		assertInvalidZoneID(t, "env:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects blank environment variable API token", func(t *testing.T) {
		assertInvalidAPIToken(t, "env:WARDEN_TEST_BLANK")
	})

	t.Run("rejects blank environment variable webhook URL", func(t *testing.T) {
		assertInvalidWebhookURL(t, "env:WARDEN_TEST_BLANK")
	})

	t.Run("rejects blank environment variable webhook header", func(t *testing.T) {
		assertInvalidWebhookHeader(t, "env:WARDEN_TEST_BLANK")
	})

	t.Run("rejects blank environment variable zone ID", func(t *testing.T) {
		assertInvalidZoneID(t, "env:WARDEN_TEST_BLANK")
	})

	t.Run("rejects missing environment variable API token", func(t *testing.T) {
		assertInvalidAPIToken(t, "env:WARDEN_TEST_MISSING_193")
	})

	t.Run("rejects missing environment variable webhook URL", func(t *testing.T) {
		assertInvalidWebhookURL(t, "env:WARDEN_TEST_MISSING_193")
	})

	t.Run("rejects missing environment variable webhook header", func(t *testing.T) {
		assertInvalidWebhookHeader(t, "env:WARDEN_TEST_MISSING_193")
	})

	t.Run("rejects missing environment variable zone ID", func(t *testing.T) {
		assertInvalidZoneID(t, "env:WARDEN_TEST_MISSING_193")
	})

	t.Run("rejects unknown reference scheme API token", func(t *testing.T) {
		assertInvalidAPIToken(t, "evn:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects unknown reference scheme webhook URL", func(t *testing.T) {
		assertInvalidWebhookURL(t, "evn:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects unknown reference scheme webhook header", func(t *testing.T) {
		assertInvalidWebhookHeader(t, "evn:WARDEN_TEST_EMPTY")
	})

	t.Run("rejects unknown reference scheme zone ID", func(t *testing.T) {
		assertInvalidZoneID(t, "evn:WARDEN_TEST_EMPTY")
	})
}

// assertInvalidAPIToken checks resolver failures for Cloudflare API credentials.
func assertInvalidAPIToken(t *testing.T, reference string) {
	t.Helper()
	_, _, err := Destinations(config.Targets{Cloudflare: map[string]config.CloudflareTarget{
		"edge": {ZoneID: strings.Repeat("a", 32), APIToken: reference},
	}})
	require.ErrorContains(t, err, `target "cloudflare.edge": api-token:`)
}

// assertInvalidWebhookURL checks resolver failures for webhook endpoints.
func assertInvalidWebhookURL(t *testing.T, reference string) {
	t.Helper()
	_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
		"receiver": {URL: reference},
	}})
	require.ErrorContains(t, err, `target "webhook.receiver": url:`)
}

// assertInvalidWebhookHeader checks resolver failures for outgoing header values.
func assertInvalidWebhookHeader(t *testing.T, reference string) {
	t.Helper()
	_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
		"receiver": {URL: "https://example.org/events", Headers: map[string]string{"X-API-Key": reference}},
	}})
	require.ErrorContains(t, err, `headers X-API-Key:`)
}

// assertInvalidZoneID checks resolver failures for Cloudflare zone identifiers.
func assertInvalidZoneID(t *testing.T, reference string) {
	t.Helper()
	_, _, err := Destinations(config.Targets{Cloudflare: map[string]config.CloudflareTarget{
		"edge": {ZoneID: reference, APIToken: "literal:valid:token"},
	}})
	require.ErrorContains(t, err, `target "cloudflare.edge": zone-id:`)
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
	t.Run("rejects CRLF header injection", func(t *testing.T) {
		t.Parallel()

		assertInvalidHeaderValue(t, "evil\r\nX-Test: yes")
	})

	t.Run("rejects NUL header byte", func(t *testing.T) {
		t.Parallel()

		assertInvalidHeaderValue(t, "\x00bad")
	})

	t.Run("rejects DEL header byte", func(t *testing.T) {
		t.Parallel()

		assertInvalidHeaderValue(t, "bad\x7f")
	})

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

// assertInvalidHeaderValue checks that invalid outbound HTTP header bytes are rejected.
func assertInvalidHeaderValue(t *testing.T, value string) {
	t.Helper()
	_, _, err := Destinations(config.Targets{Webhook: map[string]config.WebhookTarget{
		"edge": {URL: "https://example.org", Headers: map[string]string{"X-API-Key": value}},
	}})
	require.ErrorContains(t, err, "invalid HTTP header value")
}

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

func TestWebhookBodyTemplate(t *testing.T) {
	t.Parallel()

	t.Run("uses a file reference", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "slack.json.tmpl")
		require.NoError(t, os.WriteFile(path, []byte(`{"text": {{ json .IP }}}`), 0o600))

		providers, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"slack": {
					URL:          "https://example.org/webhook",
					BodyTemplate: "file:" + path,
				},
			},
		})
		require.NoError(t, err)

		provider, ok := providers["webhook.slack"].(webhook.Provider)
		require.True(t, ok)
		require.NotNil(t, provider.Template)

		body, err := provider.Template.Render(decisions.Decision{IP: "203.0.113.42"})
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"203.0.113.42"}`, string(body))

		// Templates are compiled at startup, not re-read on delivery.
		require.NoError(t, os.WriteFile(path, []byte(`{"text":"changed"}`), 0o600))
		body, err = provider.Template.Render(decisions.Decision{IP: "203.0.113.42"})
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"203.0.113.42"}`, string(body))
	})

	t.Run("accepts an explicit literal template", func(t *testing.T) {
		t.Parallel()

		providers, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"slack": {
					URL:          "https://example.org/webhook",
					BodyTemplate: `literal:{"text": {{ json .IP }}}`,
				},
			},
		})
		require.NoError(t, err)

		provider := providers["webhook.slack"].(webhook.Provider)
		require.NotNil(t, provider.Template)
		body, err := provider.Template.Render(decisions.Decision{IP: "203.0.113.42"})
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"203.0.113.42"}`, string(body))
	})

	t.Run("does not require a template", func(t *testing.T) {
		t.Parallel()

		providers, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"plain": {URL: "https://example.org/webhook"},
			},
		})
		require.NoError(t, err)
		assert.Nil(t, providers["webhook.plain"].(webhook.Provider).Template)
	})

	t.Run("rejects an unreadable template file", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"slack": {
					URL:          "https://example.org/webhook",
					BodyTemplate: "file:" + filepath.Join(t.TempDir(), "missing.tmpl"),
				},
			},
		})
		require.ErrorContains(t, err, "body-template")
		assert.ErrorContains(t, err, `webhook.slack`)
	})

	t.Run("rejects a malformed template", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"slack": {
					URL:          "https://example.org/webhook",
					BodyTemplate: `literal:{{ if .IP }}`,
				},
			},
		})
		require.ErrorContains(t, err, "body-template")
	})

	t.Run("rejects invalid rendered JSON at startup", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"slack": {
					URL:          "https://example.org/webhook",
					BodyTemplate: `literal:{"text":`,
				},
			},
		})
		require.ErrorContains(t, err, "body-template")
		assert.ErrorContains(t, err, "invalid JSON")
	})

	t.Run("rejects blank optional template source", func(t *testing.T) {
		t.Parallel()

		_, _, err := Destinations(config.Targets{
			Webhook: map[string]config.WebhookTarget{
				"slack": {
					URL:          "https://example.org/webhook",
					BodyTemplate: "   ",
				},
			},
		})
		require.ErrorContains(t, err, "body-template")
	})
}
