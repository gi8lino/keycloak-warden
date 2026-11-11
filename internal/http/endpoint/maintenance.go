package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// MaintenanceOperations provides operational DB maintenance independent of HTTP and SQLite.
type MaintenanceOperations interface {
	// Snapshot reports the last in-process maintenance attempts.
	Snapshot() maintenance.Status
	// Trigger runs the requested operation without overlapping scheduled maintenance.
	Trigger(context.Context, maintenance.Operation) error
}

// MaintenanceStatus returns scheduler state to authenticated administrators.
func MaintenanceStatus(operations MaintenanceOperations) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		httpresponse.Respond(w, http.StatusOK, operations.Snapshot())
	}
}

// RunMaintenance manually runs a supported cleanup or optimization operation.
func RunMaintenance(
	operations MaintenanceOperations,
	logger *slog.Logger,
	operation maintenance.Operation,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := operations.Trigger(ctx, operation); err != nil {
			if errors.Is(err, maintenance.ErrBusy) {
				httpresponse.Problem(w, http.StatusConflict, "Database maintenance already running.")
				return
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				httpresponse.Problem(w, http.StatusServiceUnavailable, "Database maintenance interrupted.")
				return
			}
			httpresponse.InternalServerError(logger, w, err)
			return
		}
		logger.Info(
			"database maintenance completed",
			"event", "database_maintenance_completed",
			"operation", operation,
		)
		httpresponse.Respond(w, http.StatusOK, operations.Snapshot())
	}
}
