package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/signing"
)

// failingBody exercises a read failure unrelated to the request size limit.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("body unavailable") }
func (failingBody) Close() error             { return nil }

func TestAuthenticateSnitch(t *testing.T) {
	t.Parallel()

	const secret = "shared-secret"
	const body = `{"id":"one","type":"LOGIN_ERROR"}`
	now := time.Now()
	fresh := strconv.FormatInt(now.Unix(), 10)

	tests := []struct {
		name      string
		content   string
		timestamp string
		signature string
		body      string
		want      int
	}{
		{name: "valid signature", content: "application/json", timestamp: fresh, signature: signing.Signature(secret, fresh, []byte(body)), body: body, want: http.StatusNoContent},
		{name: "JSON charset", content: "application/json; charset=utf-8", timestamp: fresh, signature: signing.Signature(secret, fresh, []byte(body)), body: body, want: http.StatusNoContent},
		{name: "missing content type", timestamp: fresh, signature: signing.Signature(secret, fresh, []byte(body)), body: body, want: http.StatusUnsupportedMediaType},
		{name: "wrong content type", content: "text/plain", timestamp: fresh, signature: signing.Signature(secret, fresh, []byte(body)), body: body, want: http.StatusUnsupportedMediaType},
		{name: "malformed content type", content: "application/json; charset=", timestamp: fresh, signature: signing.Signature(secret, fresh, []byte(body)), body: body, want: http.StatusUnsupportedMediaType},
		{name: "missing signature", content: "application/json", timestamp: fresh, body: body, want: http.StatusUnauthorized},
		{name: "wrong signature", content: "application/json", timestamp: fresh, signature: signing.Signature("other-secret", fresh, []byte(body)), body: body, want: http.StatusUnauthorized},
		{name: "body differs from signed bytes", content: "application/json", timestamp: fresh, signature: signing.Signature(secret, fresh, []byte(body)), body: body + " ", want: http.StatusUnauthorized},
		{name: "stale timestamp", content: "application/json", timestamp: strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10), body: body, want: http.StatusUnauthorized},
		{name: "future timestamp", content: "application/json", timestamp: strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10), body: body, want: http.StatusUnauthorized},
		{name: "invalid timestamp", content: "application/json", timestamp: "not-a-timestamp", body: body, want: http.StatusUnauthorized},
		{name: "oversized body", content: "application/json", timestamp: fresh, body: strings.Repeat("x", maxEventBodyBytes+1), want: http.StatusRequestEntityTooLarge},
		{name: "exact body size accepted", content: "application/json", timestamp: fresh, body: strings.Repeat("x", maxEventBodyBytes), want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			var received string
			handler := AuthenticateSnitch(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				contents, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				received = string(contents)
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", tt.content)
			request.Header.Set("X-Snitch-Timestamp", tt.timestamp)
			signature := tt.signature
			if tt.name == "exact body size accepted" {
				signature = signing.Signature(secret, fresh, []byte(tt.body))
			}
			request.Header.Set("X-Snitch-Signature", signature)
			request.Header.Set("X-Forwarded-For", "198.51.100.99")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assert.Equal(t, tt.want, response.Code)
			if tt.want == http.StatusNoContent {
				assert.Equal(t, 1, calls)
				assert.Equal(t, tt.body, received, "middleware must preserve the exact authenticated bytes")
			} else {
				assert.Zero(t, calls)
				assert.NotContains(t, response.Body.String(), secret)
			}
		})
	}

	t.Run("broken request body", func(t *testing.T) {
		t.Parallel()
		called := false
		handler := AuthenticateSnitch(secret)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		request := httptest.NewRequest(http.MethodPost, "/events", nil)
		request.Header.Set("Content-Type", "application/json")
		request.Body = failingBody{}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.False(t, called)
		assert.Contains(t, response.Body.String(), "Invalid request body")
	})
}
