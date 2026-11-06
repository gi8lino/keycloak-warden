package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// AuthenticateAdmin restricts application administration routes to a dedicated bearer token.
// It does not authenticate Snitch events or operational probes.
func AuthenticateAdmin(token string) func(http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(token))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if token == "" || !matchesBearerToken(r.Header.Values("Authorization"), expected) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="warden-admin"`)
				httpresponse.Problem(w, http.StatusUnauthorized, "Invalid administrator authentication.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// matchesBearerToken validates one Bearer header and compares its credential in constant time.
func matchesBearerToken(values []string, expected [sha256.Size]byte) bool {
	if len(values) != 1 {
		return false
	}
	scheme, value, found := strings.Cut(values[0], " ")
	if !found || value == "" || !strings.EqualFold(scheme, "Bearer") {
		return false
	}

	actual := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}
