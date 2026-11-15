package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// assertAdminAuthentication verifies status, headers, and downstream invocation.
func assertAdminAuthentication(t *testing.T, configured string, authorizations []string, wantStatus int) {
	t.Helper()

	calls := 0
	handler := AuthenticateAdmin(configured)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/bans", nil)
	for _, value := range authorizations {
		request.Header.Add("Authorization", value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assert.Equal(t, wantStatus, response.Code)
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	if wantStatus == http.StatusNoContent {
		assert.Equal(t, 1, calls)
		assert.Empty(t, response.Body.String())
		assert.Empty(t, response.Header().Get("WWW-Authenticate"))
	} else {
		assert.Zero(t, calls)
		assert.Equal(t, `Bearer realm="warden-admin"`, response.Header().Get("WWW-Authenticate"))
		assert.Contains(t, response.Body.String(), "Invalid administrator authentication")
		if configured != "" {
			assert.NotContains(t, response.Body.String(), configured)
		}
	}
}

func TestAuthenticateAdmin(t *testing.T) {
	t.Parallel()

	t.Run("valid bearer token", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Bearer secret"}, http.StatusNoContent)
	})

	t.Run("case-insensitive bearer scheme", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"bEaReR secret"}, http.StatusNoContent)
	})

	t.Run("administrative API disabled", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "", []string{"Bearer secret"}, http.StatusUnauthorized)
	})

	t.Run("missing authorization", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{}, http.StatusUnauthorized)
	})

	t.Run("wrong credential", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Bearer wrong"}, http.StatusUnauthorized)
	})

	t.Run("wrong scheme", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Basic secret"}, http.StatusUnauthorized)
	})

	t.Run("no credential", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Bearer "}, http.StatusUnauthorized)
	})

	t.Run("no scheme separator", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Bearersecret"}, http.StatusUnauthorized)
	})

	t.Run("multiple authorization headers", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Bearer secret", "Bearer secret"}, http.StatusUnauthorized)
	})

	t.Run("extra credential whitespace", func(t *testing.T) {
		t.Parallel()

		assertAdminAuthentication(t, "secret", []string{"Bearer secret "}, http.StatusUnauthorized)
	})
}
