package endpoint

import (
	"context"
	"log/slog"
	"net/http"

	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// WorkerStatus supplies the aggregated read-only worker snapshot.
type WorkerStatus interface {
	// Snapshot gathers enforcement and maintenance state without changing schedules.
	Snapshot(context.Context) (model.Workers, error)
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
