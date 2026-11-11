package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticateAdmin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		configured    string
		authorization []string
		wantStatus    int
	}{
		{name: "valid bearer token", configured: "secret", authorization: []string{"Bearer secret"}, wantStatus: http.StatusNoContent},
		{name: "case-insensitive bearer scheme", configured: "secret", authorization: []string{"bEaReR secret"}, wantStatus: http.StatusNoContent},
		{name: "administrative API disabled", authorization: []string{"Bearer secret"}, wantStatus: http.StatusUnauthorized},
		{name: "missing authorization", configured: "secret", wantStatus: http.StatusUnauthorized},
		{name: "wrong credential", configured: "secret", authorization: []string{"Bearer wrong"}, wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", configured: "secret", authorization: []string{"Basic secret"}, wantStatus: http.StatusUnauthorized},
		{name: "no credential", configured: "secret", authorization: []string{"Bearer "}, wantStatus: http.StatusUnauthorized},
		{name: "no scheme separator", configured: "secret", authorization: []string{"Bearersecret"}, wantStatus: http.StatusUnauthorized},
		{name: "multiple authorization headers", configured: "secret", authorization: []string{"Bearer secret", "Bearer secret"}, wantStatus: http.StatusUnauthorized},
		{name: "extra credential whitespace", configured: "secret", authorization: []string{"Bearer secret "}, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			handler := AuthenticateAdmin(tt.configured)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodGet, "/bans", nil)
			for _, value := range tt.authorization {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assert.Equal(t, tt.wantStatus, response.Code)
			assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			if tt.wantStatus == http.StatusNoContent {
				assert.Equal(t, 1, calls)
				assert.Empty(t, response.Body.String())
				assert.Empty(t, response.Header().Get("WWW-Authenticate"))
			} else {
				assert.Zero(t, calls)
				assert.Equal(t, `Bearer realm="warden-admin"`, response.Header().Get("WWW-Authenticate"))
				assert.Contains(t, response.Body.String(), "Invalid administrator authentication")
				if tt.configured != "" {
					assert.NotContains(t, response.Body.String(), tt.configured)
				}
			}
		})
	}
}
