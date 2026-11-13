package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containeroo/notifykit/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestProviderApply(t *testing.T) {
	t.Parallel()

	t.Run("sends configured headers and desired revision", func(t *testing.T) {
		t.Parallel()

		want := decisions.Decision{
			ID:        "stable",
			IP:        "203.0.113.2",
			Revision:  3,
			State:     decisions.StateUnbanned,
			ExpiresAt: time.Now().UTC(),
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
			assert.Equal(t, "warden", r.Header.Get("X-Source"))
			assert.Empty(t, r.Header.Get("X-Warden-Signature"))
			assert.Empty(t, r.Header.Get("X-Warden-Timestamp"))
			var got decisions.Decision
			assert.NoError(t, json.Unmarshal(body, &got))
			assert.Equal(t, want, got)
			assert.NotContains(t, string(body), `"failures"`)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		p := Provider{
			URL:     server.URL,
			Headers: http.Header{"Authorization": {"Bearer token"}, "X-Source": {"warden"}},
			Client:  server.Client(),
		}
		require.NoError(t, p.Apply(t.Context(), want))
	})

	t.Run("works without headers", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		p := Provider{URL: server.URL, Client: server.Client()}
		require.NoError(t, p.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}))
	})

	t.Run("rejects unknown desired state before sending webhook", func(t *testing.T) {
		t.Parallel()

		p := Provider{}
		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{}), "invalid decision state")
	})

	t.Run("non-success response propagates to dispatcher", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
		defer server.Close()
		p := Provider{URL: server.URL, Client: server.Client()}
		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned}), "503")
	})
}

func TestProviderTemplate(t *testing.T) {
	t.Parallel()

	t.Run("default body preserves decision JSON", func(t *testing.T) {
		t.Parallel()

		decision := decisions.Decision{
			ID:        "decision-id",
			Revision:  7,
			IP:        "203.0.113.42",
			State:     decisions.StateBanned,
			ExpiresAt: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
		}

		body, err := (Provider{}).renderBody(decision)
		require.NoError(t, err)

		want, err := json.Marshal(decision)
		require.NoError(t, err)
		assert.Equal(t, want, body)
	})

	t.Run("renders a Slack style JSON payload with escaped text", func(t *testing.T) {
		t.Parallel()

		tmpl, err := templates.ParseTemplate(
			"slack",
			`{"text": {{ json (printf "Blocked %s: %s" .IP .ID) }}}`,
			templates.WithDefaultFuncs(),
		)
		require.NoError(t, err)

		received := make(chan map[string]string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			var payload map[string]string
			if !assert.NoError(t, json.Unmarshal(body, &payload)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			received <- payload
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		provider := Provider{
			URL:      server.URL,
			Client:   server.Client(),
			Template: tmpl,
		}
		decision := decisions.Decision{
			ID:       "quoted \"id\"\nnew line",
			Revision: 5,
			IP:       "203.0.113.42",
			State:    decisions.StateBanned,
		}

		require.NoError(t, provider.Apply(t.Context(), decision))
		assert.Equal(t, "Blocked 203.0.113.42: quoted \"id\"\nnew line", (<-received)["text"])
	})

	t.Run("renders different bodies for ban and release", func(t *testing.T) {
		t.Parallel()

		tmpl, err := templates.ParseTemplate(
			"state",
			`{"text": {{ if eq .State "banned" }}{{ json "banned" }}{{ else }}{{ json "released" }}{{ end }}}`,
			templates.WithDefaultFuncs(),
		)
		require.NoError(t, err)

		provider := Provider{Template: tmpl}
		require.NoError(t, provider.ValidateTemplate())

		banBody, err := provider.renderBody(decisions.Decision{State: decisions.StateBanned})
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"banned"}`, string(banBody))

		releaseBody, err := provider.renderBody(decisions.Decision{State: decisions.StateUnbanned})
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"released"}`, string(releaseBody))
	})

	t.Run("rejects invalid JSON before HTTP request", func(t *testing.T) {
		t.Parallel()

		tmpl, err := templates.ParseTemplate("invalid", `{"text":`, templates.WithDefaultFuncs())
		require.NoError(t, err)

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		provider := Provider{URL: server.URL, Client: server.Client(), Template: tmpl}
		err = provider.Apply(t.Context(), decisions.Decision{State: decisions.StateBanned})
		require.ErrorContains(t, err, "invalid JSON")
		assert.Zero(t, requests.Load())
	})

	t.Run("rejects oversized rendered body", func(t *testing.T) {
		t.Parallel()

		tmpl, err := templates.ParseTemplate(
			"large",
			`{"text": "`+strings.Repeat("x", maxBodyBytes)+`"}`,
		)
		require.NoError(t, err)

		provider := Provider{Template: tmpl}
		require.ErrorContains(t, provider.ValidateTemplate(), "64 KiB")
	})

	t.Run("propagates template execution errors", func(t *testing.T) {
		t.Parallel()

		tmpl, err := templates.ParseTemplate("missing-field", `{"text": {{ json .MissingField }}}`, templates.WithDefaultFuncs())
		require.NoError(t, err)

		provider := Provider{Template: tmpl}
		require.ErrorContains(t, provider.ValidateTemplate(), "render webhook body")
	})

	t.Run("checks both states before startup", func(t *testing.T) {
		t.Parallel()

		tmpl, err := templates.ParseTemplate("only-ban-valid", `{{ if eq .State "banned" }}{}{{ else }}not-json{{ end }}`)
		require.NoError(t, err)

		provider := Provider{Template: tmpl}
		require.ErrorContains(t, provider.ValidateTemplate(), "unbanned state")
	})
}
