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

// Ready reports whether the database and enforcement worker are operational.
func Ready(prober ReadinessProber, enforcementDone <-chan struct{}, optionalWorkers ...<-chan struct{}) http.HandlerFunc {
	if enforcementDone == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Enforcement worker unavailable.")
		}
	}

	if prober == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Database unavailable.")
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-enforcementDone:
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Enforcement worker unavailable.")
			return
		default:
		}

		for _, done := range optionalWorkers {
			select {
			case <-done:
				httpresponse.Problem(w, http.StatusServiceUnavailable, "Notification worker unavailable.")
				return
			default:
			}
		}

		if err := prober.Ping(r.Context()); err != nil {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Database unavailable.")
			return
		}

		httpresponse.Respond(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
