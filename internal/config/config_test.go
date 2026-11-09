package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts a valid detection rule and destination", func(t *testing.T) {
		t.Parallel()
		cfg := Config{
			Rule:    detection.Rule{Threshold: 5, Window: time.Minute, Ban: 15 * time.Minute},
			Targets: Targets{Webhook: map[string]WebhookTarget{"ops": {URL: "https://example.org"}}},
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("rejects a missing detection threshold", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Rule: detection.Rule{Window: time.Minute, Ban: 15 * time.Minute}}
		require.ErrorContains(t, cfg.Validate(), "threshold")
	})

	t.Run("rejects invalid target headers before initialization", func(t *testing.T) {
		t.Parallel()
		cfg := Config{
			Rule: detection.Rule{Threshold: 5, Window: time.Minute, Ban: 15 * time.Minute},
			Targets: Targets{Webhook: map[string]WebhookTarget{
				"ops": {URL: "https://example.org", Headers: map[string]string{"Content-Type": "text/plain"}},
			}},
		}
		require.ErrorContains(t, cfg.Validate(), "Content-Type is reserved")
	})

	t.Run("rejects valid detection rules without destinations", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Rule: detection.Rule{Threshold: 5, Window: time.Minute, Ban: 15 * time.Minute}}
		require.ErrorContains(t, cfg.Validate(), "at least one")
	})
}

func TestTargetsValidate(t *testing.T) {
	t.Parallel()

	t.Run("requires at least one destination", func(t *testing.T) {
		t.Parallel()
		require.ErrorContains(t, (Targets{}).Validate(), "at least one")
	})

	t.Run("allows arbitrary valid HTTP headers except Content-Type", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{
			"ops": {URL: "env:WEBHOOK_URL", Headers: map[string]string{
				"Authorization":       "env:WEBHOOK_AUTH",
				"Host":                "example.org",
				"Content-Length":      "42",
				"Transfer-Encoding":   "chunked",
				"Proxy-Authorization": "token",
				"X-API_Key":           "literal:custom:value",
			}},
		}}
		require.NoError(t, targets.Validate())
	})

	rejectHeaderName := func(t *testing.T, name string) {
		t.Helper()
		targets := Targets{Webhook: map[string]WebhookTarget{
			"ops": {URL: "https://example.org", Headers: map[string]string{name: "value"}},
		}}
		require.ErrorContains(t, targets.Validate(), "headers")
	}

	t.Run("rejects empty header name", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "")
	})
	t.Run("rejects header name containing spaces", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "X Bad")
	})
	t.Run("rejects header name containing a colon", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "X:Bad")
	})
	t.Run("rejects header name containing a newline", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "X\nBad")
	})
	t.Run("rejects reserved Content-Type header", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "Content-Type")
	})
	t.Run("rejects lowercase content-type header", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "content-type")
	})
	t.Run("rejects uppercase CONTENT-TYPE header", func(t *testing.T) {
		t.Parallel()
		rejectHeaderName(t, "CONTENT-TYPE")
	})

	t.Run("reserves Content-Type explicitly", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{
			"ops": {URL: "https://example.org", Headers: map[string]string{"cOnTeNt-TyPe": "text/plain"}},
		}}
		require.ErrorContains(t, targets.Validate(), "Content-Type is reserved")
	})

	t.Run("rejects duplicate header names case-insensitively", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{
			"ops": {URL: "https://example.org", Headers: map[string]string{"x-api-key": "a", "X-API-Key": "b"}},
		}}
		require.ErrorContains(t, targets.Validate(), "duplicate header name")
	})

	rejectWebhookName := func(t *testing.T, name string) {
		t.Helper()
		targets := Targets{Webhook: map[string]WebhookTarget{name: {URL: "https://example.org"}}}
		require.ErrorContains(t, targets.Validate(), "name")
	}

	t.Run("rejects empty webhook target name", func(t *testing.T) {
		t.Parallel()
		rejectWebhookName(t, "")
	})
	t.Run("rejects whitespace-only webhook target name", func(t *testing.T) {
		t.Parallel()
		rejectWebhookName(t, " ")
	})
	t.Run("rejects webhook target name containing spaces", func(t *testing.T) {
		t.Parallel()
		rejectWebhookName(t, "bad name")
	})
	t.Run("rejects webhook target name containing a newline", func(t *testing.T) {
		t.Parallel()
		rejectWebhookName(t, "bad\nname")
	})

	t.Run("rejects invalid Cloudflare target name", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Cloudflare: map[string]CloudflareTarget{
			"bad name": {ZoneID: strings.Repeat("a", 32), APIToken: "token"},
		}}
		require.ErrorContains(t, targets.Validate(), "name")
	})

	t.Run("accepts slashes in webhook target names", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{"ops/alerts": {URL: "https://example.org"}}}
		require.NoError(t, targets.Validate())
	})
	t.Run("accepts slashes in Cloudflare target names", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Cloudflare: map[string]CloudflareTarget{
			"primary/zone": {ZoneID: strings.Repeat("a", 32), APIToken: "token"},
		}}
		require.NoError(t, targets.Validate())
	})

	t.Run("rejects empty webhook URL", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{"ops": {}}}
		assert.ErrorContains(t, targets.Validate(), "url")
	})
	t.Run("rejects empty header reference", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{
			"ops": {URL: "https://example.org", Headers: map[string]string{"X-Key": " "}},
		}}
		assert.ErrorContains(t, targets.Validate(), "headers")
	})
	t.Run("rejects empty Cloudflare zone", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Cloudflare: map[string]CloudflareTarget{"edge": {APIToken: "token"}}}
		assert.ErrorContains(t, targets.Validate(), "zone-id")
	})
	t.Run("rejects empty Cloudflare token", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Cloudflare: map[string]CloudflareTarget{"edge": {ZoneID: strings.Repeat("a", 32)}}}
		assert.ErrorContains(t, targets.Validate(), "api-token")
	})

	t.Run("returns deterministic first target error", func(t *testing.T) {
		t.Parallel()
		targets := Targets{
			Webhook:    map[string]WebhookTarget{"zeta": {}, "alpha": {}},
			Cloudflare: map[string]CloudflareTarget{"aaa": {}},
		}
		require.ErrorContains(t, targets.Validate(), `target "webhook.alpha": url:`)
	})

	t.Run("returns deterministic first header error", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Webhook: map[string]WebhookTarget{
			"ops": {URL: "https://example.org", Headers: map[string]string{"Z-Bad": "", "A-Bad": ""}},
		}}
		require.ErrorContains(t, targets.Validate(), `headers A-Bad:`)
	})
}
