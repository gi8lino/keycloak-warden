package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containeroo/notifykit/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestProviderResponseRule(t *testing.T) {
	t.Parallel()

	t.Run("no rule accepts HTTP 200 even when Slack says false", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
		}))
		defer server.Close()

		provider := Provider{URL: server.URL, Client: server.Client()}
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}))
	})

	t.Run("no rule still rejects non 2xx status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"secret"}`))
		}))
		defer server.Close()

		provider := Provider{URL: server.URL, Client: server.Client()}
		err := provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned})
		require.ErrorContains(t, err, "403")
		assert.NotContains(t, err.Error(), "secret")
	})

	t.Run("rule accepts HTTP 200 with JSON true", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer server.Close()

		rule := response.Rule{JSON: &response.JSON{
			Pointer:      "/ok",
			Equals:       json.RawMessage(`true`),
			ErrorPointer: "/error",
		}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}))
	})

	t.Run("rule rejects Slack HTTP 200 failure and extracts error", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found","token":"private-secret"}`))
		}))
		defer server.Close()

		rule := response.Rule{JSON: &response.JSON{
			Pointer:      "/ok",
			Equals:       json.RawMessage(`true`),
			ErrorPointer: "/error",
		}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		err := provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned})
		require.ErrorContains(t, err, "channel_not_found")
		assert.NotContains(t, err.Error(), "private-secret")
	})

	t.Run("extracts JSON error on an unexpected HTTP status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth","sensitive":"private-secret"}`))
		}))
		defer server.Close()

		rule := response.Rule{JSON: &response.JSON{
			Pointer:      "/ok",
			Equals:       json.RawMessage(`true`),
			ErrorPointer: "/error",
		}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		err := provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned})
		require.ErrorContains(t, err, "403")
		assert.ErrorContains(t, err, "invalid_auth")
		assert.NotContains(t, err.Error(), "private-secret")
	})

	t.Run("rule rejects invalid JSON", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer server.Close()

		rule := response.Rule{JSON: &response.JSON{
			Pointer: "/ok",
			Equals:  json.RawMessage(`true`),
		}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.Error(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateUnbanned}))
	})

	t.Run("rule allows explicitly configured non 2xx response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer server.Close()

		rule := response.Rule{StatusCodes: []int{http.StatusTeapot}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}))
	})

	t.Run("status-only rule rejects unconfigured 2xx response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		rule := response.Rule{StatusCodes: []int{http.StatusAccepted}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.ErrorContains(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}), "204")
	})

	t.Run("text rule matches exact response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		defer server.Close()

		expected := "ok"
		rule := response.Rule{Text: &response.Text{Equals: &expected}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}))
	})

	t.Run("text rule extracts sanitized bounded error details", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Invalid key\n" + strings.Repeat("x", 1000)))
		}))
		defer server.Close()

		expected := "ok"
		rule := response.Rule{Text: &response.Text{Equals: &expected}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		err := provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned})
		require.ErrorContains(t, err, "Invalid key")
		assert.NotContains(t, err.Error(), "\n")
		assert.Less(t, len(err.Error()), 400)
	})

	t.Run("rejects oversized response bodies when matching", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
		}))
		defer server.Close()

		expected := "ok"
		rule := response.Rule{Text: &response.Text{Equals: &expected}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.ErrorContains(t, provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}), "64 KiB")
	})
}
