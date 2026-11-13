package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadResponseRule loads a response rule through Warden's strict YAML configuration.
func loadResponseRule(t *testing.T, body string) (WebhookResponse, error) {
	t.Helper()

	cfg, err := Load(writeConfig(t, "rule:\n  threshold: 2\n  window: 1m\n  ban: 15m\ntargets:\n  webhook:\n    ops:\n      url: https://example.org\n      response:\n"+body))
	if err != nil {
		return WebhookResponse{}, err
	}

	target := cfg.Targets.Webhook["ops"]
	if target.Response == nil {
		t.Fatal("expected response rule")
	}
	return *target.Response, cfg.Validate()
}

func TestWebhookResponseRule(t *testing.T) {
	t.Parallel()

	t.Run("preserves 2xx as default", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        {}\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.NoError(t, rule.Evaluate(204, nil))
		assert.Error(t, rule.Evaluate(400, nil))
	})

	t.Run("parses status codes and inclusive ranges with httpkit", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        status-codes: '200-202,207'\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.Equal(t, []int{200, 201, 202, 207}, rule.StatusCodes)
		assert.NoError(t, rule.Evaluate(207, nil))
		assert.Error(t, rule.Evaluate(204, nil))
	})

	t.Run("parses exact text", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        text:\n          equals: ok\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.NoError(t, rule.Evaluate(200, []byte("ok")))
		assert.Error(t, rule.Evaluate(200, []byte("ok\n")))
	})

	t.Run("parses plain text substring", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        text:\n          contains: accepted\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.NoError(t, rule.Evaluate(202, []byte("request accepted")))
	})

	t.Run("preserves JSON boolean types and extracts Slack error", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        json:\n          pointer: /ok\n          equals: true\n          error-pointer: /error\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.JSONEq(t, `true`, string(rule.JSON.Equals))
		assert.NoError(t, rule.Evaluate(200, []byte(`{"ok":true}`)))
		assert.ErrorContains(t, rule.Evaluate(200, []byte(`{"ok":false,"error":"channel_not_found"}`)), "channel_not_found")
		assert.Error(t, rule.Evaluate(200, []byte(`{"ok":"true"}`)))
	})

	t.Run("supports nested JSON pointers and arrays", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        json:\n          pointer: /results/0/delivery/accepted\n          equals: true\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.NoError(t, rule.Evaluate(200, []byte(`{"results":[{"delivery":{"accepted":true}}]}`)))
	})

	t.Run("accepts explicit JSON null", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        json:\n          pointer: /error\n          equals: null\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.Equal(t, "null", string(rule.JSON.Equals))
		assert.NoError(t, rule.Evaluate(200, []byte(`{"error":null}`)))
		assert.Error(t, rule.Evaluate(200, []byte(`{}`)))
	})

	t.Run("rejects missing JSON equals", func(t *testing.T) {
		t.Parallel()

		_, err := loadResponseRule(t, "        json:\n          pointer: /ok\n")
		require.ErrorContains(t, err, "json.equals")
	})

	t.Run("rejects conflicting response matchers", func(t *testing.T) {
		t.Parallel()

		_, err := loadResponseRule(t, "        text:\n          equals: ok\n        json:\n          pointer: /ok\n          equals: true\n")
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("rejects invalid JSON pointers", func(t *testing.T) {
		t.Parallel()

		_, err := loadResponseRule(t, "        json:\n          pointer: bad-pointer\n          equals: true\n")
		require.ErrorContains(t, err, "JSON pointer")
	})

	t.Run("rejects oversized status ranges before expansion", func(t *testing.T) {
		t.Parallel()

		_, err := loadResponseRule(t, "        status-codes: '200-99999999'\n")
		require.ErrorContains(t, err, "allowed range 200-599")
	})

	t.Run("rejects invalid status expressions", func(t *testing.T) {
		t.Parallel()

		_, err := loadResponseRule(t, "        status-codes: '200-201,broken'\n")
		require.ErrorContains(t, err, "status-codes")
	})

	t.Run("rejects unknown response fields", func(t *testing.T) {
		t.Parallel()

		_, err := loadResponseRule(t, "        json:\n          pointer: /ok\n          equals: true\n          typo: invalid\n")
		require.ErrorContains(t, err, "invalid Warden YAML")
	})

	t.Run("converts nested expected YAML to typed JSON", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        json:\n          pointer: /result\n          equals:\n            accepted: true\n            count: 2\n            reasons:\n              - accepted\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		require.NotNil(t, rule.JSON)
		assert.JSONEq(t, `{"accepted":true,"count":2,"reasons":["accepted"]}`, string(rule.JSON.Equals))
		assert.NoError(t, rule.Evaluate(200, []byte(`{"result":{"accepted":true,"count":2,"reasons":["accepted"]}}`)))
		assert.Error(t, rule.Evaluate(200, []byte(`{"result":{"accepted":true,"count":"2","reasons":["accepted"]}}`)))
	})

	t.Run("combines a text matcher with custom status codes", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadResponseRule(t, "        status-codes: '202,207'\n        text:\n          equals: accepted\n")
		require.NoError(t, err)

		rule, err := cfg.Rule()
		require.NoError(t, err)
		assert.NoError(t, rule.Evaluate(207, []byte("accepted")))
		assert.Error(t, rule.Evaluate(200, []byte("accepted")))
		assert.Error(t, rule.Evaluate(207, []byte("rejected")))
	})
}
