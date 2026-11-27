package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// NotificationQueries exposes read-only occurrence delivery history.
type NotificationQueries interface {
	// Deliveries reads one cursor-paginated page of notification deliveries.
	Deliveries(context.Context, int64) (model.NotificationPage, error)
	// Attempts reads one page of completed sends for a notification.
	Attempts(context.Context, int64, int64) (model.NotificationAttemptPage, error)
}

// NotificationRetries exposes explicit retry admission for exhausted occurrences.
type NotificationRetries interface {
	// Retry requeues an eligible occurrence with a fresh attempt budget.
	Retry(context.Context, int64, string, time.Time) error
}

// NotificationHistory lists retained occurrence delivery records.
func NotificationHistory(service NotificationQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		before, ok := notificationCursor(w, r, "before-id")
		if !ok {
			return
		}
		result, err := service.Deliveries(r.Context(), before)
		if writeOverviewError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, result)
	}
}

// NotificationAttempts lists one occurrence's recorded outbound sends.
func NotificationAttempts(service NotificationQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := notificationID(w, r)
		if !ok {
			return
		}
		before, ok := notificationCursor(w, r, "before-number")
		if !ok {
			return
		}
		result, err := service.Attempts(r.Context(), id, before)
		if writeOverviewError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, result)
	}
}

// RetryNotification validates the request and requeues an exhausted occurrence.
func RetryNotification(service NotificationRetries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := notificationID(w, r)
		if !ok {
			return
		}
		var request model.NotificationRetryRequest
		if !decodeAdminPayload(w, r, &request, "Invalid notification retry request.", "Retry request is too large.") {
			return
		}
		err := service.Retry(r.Context(), id, request.Actor, time.Now())
		switch {
		case errors.Is(err, notifications.ErrRetryInvalid):
			httpresponse.Problem(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, notifications.ErrRetryConflict):
			httpresponse.Problem(w, http.StatusConflict, err.Error())
		case err != nil:
			logger.Error("notification retry failed", "error", err)
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Notification retry unavailable.")
		default:
			logger.Info("notification retry queued", "event", "notification_retry_queued", "delivery_id", id)
			httpresponse.Respond(w, http.StatusAccepted, model.RetryResponse{Queued: true})
		}
	}
}

// notificationID validates the delivery path segment.
func notificationID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		httpresponse.Problem(w, http.StatusBadRequest, "Invalid notification delivery ID.")
		return 0, false
	}
	return id, true
}

// notificationCursor rejects unknown or repeated parameters and invalid cursors.
func notificationCursor(w http.ResponseWriter, r *http.Request, key string) (int64, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err == nil && len(values) == 0 {
		return 0, true
	}
	if err == nil && len(values) == 1 && len(values[key]) == 1 {
		value, parseErr := strconv.ParseInt(values.Get(key), 10, 64)
		if parseErr == nil && value > 0 {
			return value, true
		}
	}
	httpresponse.Problem(w, http.StatusBadRequest, "Invalid notification cursor.")
	return 0, false
}
