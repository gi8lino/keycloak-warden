package endpoint

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gi8lino/keycloak-warden/internal/application/workers"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// WorkerStatus supplies the aggregated read-only worker snapshot.
type WorkerStatus interface {
	// Snapshot gathers action and maintenance state without changing schedules.
	Snapshot(context.Context) (workers.Status, error)
}

// Workers returns worker state to an authenticated Warden administrator.
func Workers(service WorkerStatus, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, err := service.Snapshot(r.Context())
		if err != nil {
			httpresponse.InternalServerError(logger, w, err)
			return
		}
		httpresponse.Respond(w, http.StatusOK, status)
	}
}
