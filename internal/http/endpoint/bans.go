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

// maxBanBodyBytes limits administrative ban requests to 16 KiB.
const maxBanBodyBytes = 16 << 10

// BanAdministration exposes validated administrative ban operations independently of HTTP.
type BanAdministration interface {
	BanManual(context.Context, bans.ManualBanRequest, time.Time) (bans.Record, error)
	Release(context.Context, string, time.Time) (bans.Record, error)
	ListActive(context.Context, time.Time) ([]bans.Record, error)
	GetDecision(context.Context, string, time.Time) (bans.Record, error)
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
func CreateBan(service BanAdministration, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, ok := decodeBanPayload(w, r)
		if !ok {
			return
		}

		duration, err := time.ParseDuration(payload.Duration)
		if err != nil {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid ban duration.")
			return
		}

		record, err := service.BanManual(r.Context(), bans.ManualBanRequest{
			IP:       payload.IP,
			Duration: duration,
			Reason:   payload.Reason,
		}, time.Now())
		if writeBanError(w, logger, err) {
			return
		}

		logger.Info(
			"manual ban requested",
			"event", "manual_ban_requested",
			"decision_id", record.Decision.ID,
			"ip", record.Decision.IP,
			"expires_at", record.Decision.ExpiresAt,
		)
		httpresponse.Respond(w, http.StatusOK, record)
	}
}

// decodeBanPayload enforces the JSON content type, size limit, and single-object contract.
func decodeBanPayload(w http.ResponseWriter, r *http.Request) (createBanPayload, bool) {
	var payload createBanPayload
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		httpresponse.Problem(w, http.StatusUnsupportedMediaType, "Expected application/json.")
		return payload, false
	}

	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
		defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBanBodyBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&payload); err != nil {
		writeBanDecodeError(w, err, "Invalid ban request.")
		return payload, false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeBanDecodeError(w, err, "Expected exactly one JSON object.")
		return payload, false
	}

	return payload, true
}

// writeBanDecodeError distinguishes oversized bodies from malformed JSON without leaking input.
func writeBanDecodeError(w http.ResponseWriter, err error, invalidMessage string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		httpresponse.Problem(w, http.StatusRequestEntityTooLarge, "Ban request is too large.")
		return
	}
	httpresponse.Problem(w, http.StatusBadRequest, invalidMessage)
}

// ListBans returns current blocks and their independent sources.
func ListBans(service BanAdministration, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := service.ListActive(r.Context(), time.Now())
		if writeBanError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, list)
	}
}

// GetBan returns one persisted decision together with its sources and deliveries.
func GetBan(service BanAdministration, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		record, err := service.GetDecision(r.Context(), r.PathValue("id"), time.Now())
		if writeBanError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, record)
	}
}

// DeleteBan clears all active ban sources and resets detection for the decision.
func DeleteBan(service BanAdministration, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		record, err := service.Release(r.Context(), r.PathValue("id"), time.Now())
		if writeBanError(w, logger, err) {
			return
		}
		logger.Info(
			"ban sources removed",
			"event", "ban_sources_removed",
			"decision_id", record.Decision.ID,
			"ip", record.Decision.IP,
			"state", record.Decision.State,
		)
		httpresponse.Respond(w, http.StatusOK, record)
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
		logger.Error(
			"manual ban operation failed",
			"event", "manual_ban_operation_failed",
			"error", err,
		)
		httpresponse.Problem(w, http.StatusServiceUnavailable, "Administrative operation unavailable.")
	}
	return true
}
