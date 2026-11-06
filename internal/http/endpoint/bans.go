package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

const maxBanBodyBytes = 16 << 10

// BanService provides manual-ban operations independently of HTTP.
type BanService interface {
	Ban(context.Context, bans.Request, time.Time) (bans.Ban, error)
	Unban(context.Context, string, time.Time) (bans.Ban, error)
	List(context.Context, time.Time) ([]bans.Ban, error)
	Get(context.Context, string, time.Time) (bans.Ban, error)
}

// createBanPayload contains the fields decoded independently for each administrative request.
type createBanPayload struct {
	// IP is the single address requested by the operator.
	IP string `json:"ipAddress"`
	// Duration is the requested lifetime in Go duration syntax.
	Duration string `json:"duration"`
	// Reason explains why the operator requested the block.
	Reason string `json:"reason"`
}

// CreateBan creates or extends a manual ban, returning its effective decision.
func CreateBan(service BanService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload createBanPayload
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			httpresponse.Problem(w, http.StatusUnsupportedMediaType, "Expected application/json.")
			return
		}

		controller := http.NewResponseController(w)
		if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
			defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
		}

		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBanBodyBytes))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&payload); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				httpresponse.Problem(w, http.StatusRequestEntityTooLarge, "Ban request is too large.")
				return
			}
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid ban request.")
			return
		}

		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			httpresponse.Problem(w, http.StatusBadRequest, "Expected exactly one JSON object.")
			return
		}

		duration, err := time.ParseDuration(payload.Duration)
		if err != nil {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid ban duration.")
			return
		}

		view, err := service.Ban(r.Context(), bans.Request{
			IP:       payload.IP,
			Duration: duration,
			Reason:   payload.Reason,
		}, time.Now())

		if writeBanError(w, logger, err) {
			return
		}

		logger.Info(
			"manual ban requested",
			"decision_id", view.Decision.ID,
			"ip", view.Decision.IP,
			"expires_at", view.Decision.ExpiresAt,
		)
		httpresponse.Respond(w, http.StatusOK, view)
	}
}

// ListBans returns current blocks and their independent sources.
func ListBans(service BanService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := service.List(r.Context(), time.Now())
		if writeBanError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, list)
	}
}

// GetBan returns one persisted decision together with its sources and deliveries.
func GetBan(service BanService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view, err := service.Get(r.Context(), r.PathValue("id"), time.Now())
		if writeBanError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, view)
	}
}

// DeleteBan clears all active ban sources and resets detection for the decision.
func DeleteBan(service BanService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view, err := service.Unban(r.Context(), r.PathValue("id"), time.Now())
		if writeBanError(w, logger, err) {
			return
		}
		logger.Info(
			"ban sources removed",
			"decision_id", view.Decision.ID,
			"ip", view.Decision.IP,
			"remains_blocked", view.Decision.Active,
		)
		httpresponse.Respond(w, http.StatusOK, view)
	}
}

// writeBanError maps application errors to safe HTTP responses and logs infrastructure errors.
func writeBanError(w http.ResponseWriter, logger *slog.Logger, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, bans.ErrInvalid):
		httpresponse.Problem(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, bans.ErrNotFound):
		httpresponse.Problem(w, http.StatusNotFound, "Manual ban or decision not found.")
	default:
		logger.Error("manual ban operation failed", "error", err)
		httpresponse.Problem(w, http.StatusServiceUnavailable, "Administrative operation unavailable.")
	}
	return true
}
