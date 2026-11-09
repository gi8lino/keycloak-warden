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

// Ready reports whether the database and action worker are operational.
func Ready(prober ReadinessProber, workerDone <-chan struct{}) http.HandlerFunc {
	if workerDone == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Action worker unavailable.")
		}
	}
	if prober == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Database unavailable.")
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-workerDone:
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Action worker unavailable.")
			return
		default:
		}

		if err := prober.Ping(r.Context()); err != nil {
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Database unavailable.")
			return
		}

		httpresponse.Respond(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
