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

	t.Run("accepts a valid detection rule", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Rule: detection.Rule{Threshold: 5, Window: time.Minute, Ban: 15 * time.Minute}}

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
}

func TestTargetsValidate(t *testing.T) {
	t.Parallel()

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

	for _, name := range []string{"", "X Bad", "X:Bad", "X\nBad", "Content-Type", "content-type", "CONTENT-TYPE"} {
		t.Run("rejects invalid or reserved header "+name, func(t *testing.T) {
			t.Parallel()
			targets := Targets{Webhook: map[string]WebhookTarget{
				"ops": {URL: "https://example.org", Headers: map[string]string{name: "value"}},
			}}
			require.ErrorContains(t, targets.Validate(), "headers")
		})
	}

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

	for _, name := range []string{"", " ", "bad/name", "bad name", "bad\nname"} {
		t.Run("rejects invalid webhook target name "+name, func(t *testing.T) {
			t.Parallel()
			targets := Targets{Webhook: map[string]WebhookTarget{name: {URL: "https://example.org"}}}
			require.ErrorContains(t, targets.Validate(), "name")
		})
	}

	t.Run("rejects invalid cloudflare target name", func(t *testing.T) {
		t.Parallel()
		targets := Targets{Cloudflare: map[string]CloudflareTarget{"bad/name": {ZoneID: strings.Repeat("a", 32), APIToken: "token"}}}
		require.ErrorContains(t, targets.Validate(), "name")
	})

	tests := []struct {
		name    string
		targets Targets
		want    string
	}{
		{"empty webhook URL", Targets{Webhook: map[string]WebhookTarget{"ops": {}}}, "url"},
		{"empty header reference", Targets{Webhook: map[string]WebhookTarget{"ops": {URL: "https://example.org", Headers: map[string]string{"X-Key": " "}}}}, "headers"},
		{"empty Cloudflare zone", Targets{Cloudflare: map[string]CloudflareTarget{"edge": {APIToken: "token"}}}, "zone-id"},
		{"empty Cloudflare token", Targets{Cloudflare: map[string]CloudflareTarget{"edge": {ZoneID: strings.Repeat("a", 32)}}}, "api-token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.ErrorContains(t, tc.targets.Validate(), tc.want)
		})
	}
}
