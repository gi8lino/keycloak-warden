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

// Read simulates a request body read failure.
func (failingBody) Read([]byte) (int, error) { return 0, errors.New("body unavailable") }

// Close releases the fake request body without an error.
func (failingBody) Close() error { return nil }

// assertSnitchAuthentication exercises the request validator and its original-body contract.
func assertSnitchAuthentication(t *testing.T, secret, content, timestamp, signature, body string, want int) {
	t.Helper()

	calls := 0
	var received string
	handler := AuthenticateSnitch(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		contents, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received = string(contents)
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
	request.Header.Set("Content-Type", content)
	request.Header.Set("X-Snitch-Timestamp", timestamp)
	request.Header.Set("X-Snitch-Signature", signature)
	request.Header.Set("X-Forwarded-For", "198.51.100.99")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assert.Equal(t, want, response.Code)
	if want == http.StatusNoContent {
		assert.Equal(t, 1, calls)
		assert.Equal(t, body, received, "middleware must preserve the exact authenticated bytes")
	} else {
		assert.Zero(t, calls)
		assert.NotContains(t, response.Body.String(), secret)
	}
}

func TestAuthenticateSnitch(t *testing.T) {
	t.Parallel()

	const secret = "shared-secret"
	const body = `{"id":"one","type":"LOGIN_ERROR"}`
	now := time.Now()
	fresh := strconv.FormatInt(now.Unix(), 10)
	validSignature := signing.Signature(secret, fresh, []byte(body))

	t.Run("valid signature", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", fresh, validSignature, body, http.StatusNoContent)
	})

	t.Run("JSON charset", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json; charset=utf-8", fresh, validSignature, body, http.StatusNoContent)
	})

	t.Run("missing content type", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "", fresh, validSignature, body, http.StatusUnsupportedMediaType)
	})

	t.Run("wrong content type", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "text/plain", fresh, validSignature, body, http.StatusUnsupportedMediaType)
	})

	t.Run("malformed content type", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json; charset=", fresh, validSignature, body, http.StatusUnsupportedMediaType)
	})

	t.Run("missing signature", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", fresh, "", body, http.StatusUnauthorized)
	})

	t.Run("wrong signature", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", fresh, signing.Signature("other-secret", fresh, []byte(body)), body, http.StatusUnauthorized)
	})

	t.Run("body differs from signed bytes", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", fresh, validSignature, body+" ", http.StatusUnauthorized)
	})

	t.Run("stale timestamp", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10), "", body, http.StatusUnauthorized)
	})

	t.Run("future timestamp", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10), "", body, http.StatusUnauthorized)
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", "not-a-timestamp", "", body, http.StatusUnauthorized)
	})

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", fresh, "", strings.Repeat("x", maxEventBodyBytes+1), http.StatusRequestEntityTooLarge)
	})

	t.Run("exact body size accepted", func(t *testing.T) {
		t.Parallel()

		assertSnitchAuthentication(t, secret, "application/json", fresh, signing.Signature(secret, fresh, []byte(strings.Repeat("x", maxEventBodyBytes))), strings.Repeat("x", maxEventBodyBytes), http.StatusNoContent)
	})

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
