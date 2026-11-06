package endpoint

import (
	"context"
	"net/http"

	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// ReadinessProber reports whether the required database is responsive.
type ReadinessProber interface {
	Ping(context.Context) error
}

// Health provides process liveness independent of external services.
func Health() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		httpresponse.Respond(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// Ready checks the required persistent store on the management listener.
func Ready(prober ReadinessProber) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := prober.Ping(r.Context()); err != nil {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Database unavailable.")
			return
		}
		httpresponse.Respond(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
