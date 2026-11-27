package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// BanAdministration manages administrative ban operations.
type BanAdministration interface {
	BanManual(context.Context, bans.ManualBanRequest, time.Time) (model.Record, error)
	Release(context.Context, string, time.Time) (model.Record, error)
	ListActive(context.Context, time.Time) ([]model.Record, error)
	GetDecisionPage(context.Context, string, time.Time, int, int64) (model.Record, error)
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

		logger.Info("manual ban requested",
			"event", "manual_ban_requested",
			"decision_id", record.Decision.ID,
			"ip", record.Decision.IP,
			"expires_at", record.Decision.ExpiresAt,
		)
		httpresponse.Respond(w, http.StatusOK, record)
	}
}

// decodeBanPayload decodes the manual ban request.
func decodeBanPayload(w http.ResponseWriter, r *http.Request) (model.CreateBanRequest, bool) {
	var payload model.CreateBanRequest
	ok := decodeAdminPayload(w, r, &payload, "Invalid ban request.", "Ban request is too large.")
	return payload, ok
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
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid history query.")
			return
		}

		page := 1
		knownParameters := 0
		if values, ok := query["history-page"]; ok {
			knownParameters++
			if len(values) != 1 {
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid history page.")
				return
			}

			page, err = strconv.Atoi(values[0])
			if err != nil {
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid history page.")
				return
			}
		}

		var throughRevision int64
		if values, ok := query["history-through-revision"]; ok {
			knownParameters++
			if len(values) != 1 {
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid history revision.")
				return
			}

			throughRevision, err = strconv.ParseInt(values[0], 10, 64)
			if err != nil || throughRevision < 1 {
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid history revision.")
				return
			}
		}

		if len(query) != knownParameters {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid history query.")
			return
		}

		record, err := service.GetDecisionPage(r.Context(), r.PathValue("id"), time.Now(), page, throughRevision)
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
		logger.Info("ban sources removed",
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
	case errors.Is(err, bans.ErrProtected), errors.Is(err, bans.ErrObserveOnly):
		httpresponse.Problem(w, http.StatusConflict, err.Error())
	case errors.Is(err, bans.ErrInvalid):
		httpresponse.Problem(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, bans.ErrNotFound):
		httpresponse.Problem(w, http.StatusNotFound, "Manual ban or decision not found.")
	default:
		logger.Error("manual ban operation failed",
			"event", "manual_ban_operation_failed",
			"error", err,
		)
		httpresponse.Problem(w, http.StatusServiceUnavailable, "Administrative operation unavailable.")
	}
	return true
}
