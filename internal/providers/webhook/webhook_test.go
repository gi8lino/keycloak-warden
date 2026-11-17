package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/containeroo/notifykit/response"
	"github.com/containeroo/notifykit/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

func TestProviderApply(t *testing.T) {
	t.Parallel()

	t.Run("sends configured headers and desired revision", func(t *testing.T) {
		t.Parallel()

		want := decisions.Decision{
			ID:        "stable",
			IP:        "203.0.113.2",
			Revision:  3,
			State:     decisionstate.StateUnbanned,
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
		require.NoError(t, p.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}))
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
		require.ErrorContains(t, p.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}), "503")
	})
}

// failingRoundTripper returns a selected transport error without using the network.
type failingRoundTripper struct {
	// err models the underlying HTTP transport failure, including unsafe details.
	err error
}

// RoundTrip fails before a response is received.
func (f failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

// privateTimeoutError simulates a network timeout with unsafe diagnostic text.
type privateTimeoutError struct{}

// Error returns the transport diagnostic used by the test.
func (privateTimeoutError) Error() string {
	return "timeout contacting private.example with secret-token"
}

// Timeout identifies this fake transport error as a timeout.
func (privateTimeoutError) Timeout() bool { return true }

// Temporary reports the fake network error as transient.
func (privateTimeoutError) Temporary() bool { return true }

// failingWebhookProvider models credentials in both the URL and headers so
// transport error tests can verify they never appear in returned diagnostics.
func failingWebhookProvider(err error) Provider {
	return Provider{
		URL: "http://user:password@private.example/notify?token=query-secret",
		Headers: http.Header{
			"Authorization": {"Bearer header-secret"},
			"X-Secret":      {"private-header"},
		},
		Client: &http.Client{Transport: failingRoundTripper{err: err}},
	}
}

func TestProviderTransportErrors(t *testing.T) {
	t.Parallel()

	decision := decisions.Decision{State: decisionstate.StateBanned}

	t.Run("reports DNS name not found without leaking the hostname", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.DNSError{
			Err:        "lookup private.example with secret details",
			Name:       "private.example",
			IsNotFound: true,
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: DNS name not found")
		assert.NotContains(t, err.Error(), "private.example")
		var unsafeDNS *net.DNSError
		assert.NotErrorAs(t, err, &unsafeDNS)
	})

	t.Run("reports DNS lookup timeout", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.DNSError{
			Name:      "private.example",
			Err:       "secret DNS error text",
			IsTimeout: true,
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: DNS lookup timed out")
	})

	t.Run("reports other DNS lookup failures", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.DNSError{
			Name: "private.example",
			Err:  "secret DNS diagnostic",
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: DNS lookup failed")
	})

	t.Run("reports request deadline without exposing transport details", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(context.DeadlineExceeded)
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: request timed out: context deadline exceeded")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("reports connection timeout without leaking underlying details", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.OpError{
			Op:  "dial",
			Err: privateTimeoutError{},
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: connection timed out")
		assert.NotContains(t, err.Error(), "secret-token")
	})

	t.Run("reports canceled request", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(context.Canceled)
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: context canceled")
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("reports certificate trust failures without certificate details", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(x509.UnknownAuthorityError{Cert: &x509.Certificate{}})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: TLS certificate authority not trusted")
	})

	t.Run("reports TLS hostname mismatch without leaking the host", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(x509.HostnameError{
			Certificate: &x509.Certificate{},
			Host:        "sensitive.internal",
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: TLS certificate hostname mismatch")
		assert.NotContains(t, err.Error(), "sensitive.internal")
	})

	t.Run("reports other certificate validation failures", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(x509.CertificateInvalidError{
			Cert:   &x509.Certificate{},
			Reason: x509.Expired,
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: TLS certificate invalid")
	})

	t.Run("reports TLS handshake failure without raw protocol data", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(tls.RecordHeaderError{Msg: "secret response bytes"})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: TLS handshake failed")
	})

	t.Run("reports connection refused without leaking remote address", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.OpError{
			Op:   "dial",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.45"), Port: 9000},
			Err:  syscall.ECONNREFUSED,
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: connection refused")
		assert.ErrorIs(t, err, syscall.ECONNREFUSED)
		assert.NotContains(t, err.Error(), "10.0.0.45")
		var unsafeURL *url.Error
		assert.NotErrorAs(t, err, &unsafeURL)
	})

	t.Run("reports network unreachable", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.OpError{
			Op:  "dial",
			Err: syscall.ENETUNREACH,
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: "+syscall.ENETUNREACH.Error())
		assert.ErrorIs(t, err, syscall.ENETUNREACH)
	})

	t.Run("reports connection reset", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.OpError{
			Op:  "read",
			Err: syscall.ECONNRESET,
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: "+syscall.ECONNRESET.Error())
		assert.ErrorIs(t, err, syscall.ECONNRESET)
	})

	t.Run("reports an unexpected connection close", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(io.ErrUnexpectedEOF)
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: connection closed unexpectedly: unexpected EOF")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("reports unknown connection errors without printing their text", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(&net.OpError{
			Op:  "dial",
			Err: errors.New("internal address and credentials secret-token"),
		})
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: connection error")
		assert.NotContains(t, err.Error(), "secret-token")
	})

	t.Run("never returns arbitrary error text or credential-bearing URL", func(t *testing.T) {
		t.Parallel()

		p := failingWebhookProvider(errors.New("failed to dial private.example: secret header-secret private-header"))
		err := p.Apply(t.Context(), decision)

		require.EqualError(t, err, "webhook transport failed: network error")
		assert.NotContains(t, err.Error(), "user:password")
		assert.NotContains(t, err.Error(), "query-secret")
		assert.NotContains(t, err.Error(), "header-secret")
		assert.NotContains(t, err.Error(), "private-header")
		assert.NotContains(t, err.Error(), "private.example")
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
			State:     decisionstate.StateBanned,
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
			State:    decisionstate.StateBanned,
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

		banBody, err := provider.renderBody(decisions.Decision{State: decisionstate.StateBanned})
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"banned"}`, string(banBody))

		releaseBody, err := provider.renderBody(decisions.Decision{State: decisionstate.StateUnbanned})
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
		err = provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned})
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

func TestProviderResponseRule(t *testing.T) {
	t.Parallel()

	t.Run("no rule accepts HTTP 200 even when Slack says false", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
		}))
		defer server.Close()

		provider := Provider{URL: server.URL, Client: server.Client()}
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}))
	})

	t.Run("no rule still rejects non 2xx status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"secret"}`))
		}))
		defer server.Close()

		provider := Provider{URL: server.URL, Client: server.Client()}
		err := provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned})
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
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}))
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
		err := provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned})
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
		err := provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned})
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
		assert.Error(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateUnbanned}))
	})

	t.Run("rule allows explicitly configured non 2xx response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer server.Close()

		rule := response.Rule{StatusCodes: []int{http.StatusTeapot}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}))
	})

	t.Run("status-only rule rejects unconfigured 2xx response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		rule := response.Rule{StatusCodes: []int{http.StatusAccepted}}
		provider := Provider{URL: server.URL, Client: server.Client(), Response: &rule}
		assert.ErrorContains(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}), "204")
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
		assert.NoError(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}))
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
		err := provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned})
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
		assert.ErrorContains(t, provider.Apply(t.Context(), decisions.Decision{State: decisionstate.StateBanned}), "64 KiB")
	})
}
