package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// RetryOperations exposes validated explicit retries.
type RetryOperations interface {
	Retry(context.Context, model.RetryRequest, time.Time) error
}

// RetryDelivery queues one exhausted current delivery via the application service.
func RetryDelivery(service RetryOperations, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request model.RetryRequest
		if !decodeAdminPayload(w, r, &request, "Invalid retry request.", "Retry request is too large.") {
			return
		}
		err := service.Retry(r.Context(), request, time.Now())
		switch {
		case errors.Is(err, enforcement.ErrRetryInvalid):
			httpresponse.Problem(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, enforcement.ErrRetryConflict):
			httpresponse.Problem(w, http.StatusConflict, err.Error())
		case err != nil:
			logger.Error("delivery retry failed", "error", err)
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Retry unavailable.")
		default:
			logger.Info("delivery retry queued", "event", "delivery_retry_queued", "decision_id", request.DecisionID, "revision", request.Revision, "destination", request.Destination, "actor", request.Actor)
			httpresponse.Respond(w, http.StatusAccepted, model.RetryResponse{Queued: true})
		}
	}
}

// OperationalQueries exposes read-only operational projections.
type OperationalQueries interface {
	Health(context.Context) ([]model.DestinationHealth, error)
	Timeline(context.Context, string, int) (model.TimelinePage, error)
	Incidents(context.Context, overview.IncidentQuery) (model.IncidentPage, error)
}

// DeliveryHealth returns current counts grouped by destination.
func DeliveryHealth(service OperationalQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := service.Health(r.Context())
		if writeOverviewError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, result)
	}
}

// DecisionTimeline returns persisted chronological decision activity.
func DecisionTimeline(service OperationalQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, page, ok := overviewQuery(w, r)
		if !ok {
			return
		}
		result, err := service.Timeline(r.Context(), r.PathValue("id"), page)
		if errors.Is(err, overview.ErrTimelineNotFound) {
			httpresponse.Problem(w, http.StatusNotFound, "Decision not found.")
			return
		}
		if writeOverviewError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, result)
	}
}

// Incidents returns recorded named rule threshold hits.
func Incidents(service OperationalQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query, err := parseIncidentQuery(r.URL.RawQuery)
		if err != nil {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid incident query.")
			return
		}
		result, err := service.Incidents(r.Context(), query)
		if writeOverviewError(w, logger, err) {
			return
		}
		httpresponse.Respond(w, http.StatusOK, result)
	}
}

// parseIncidentQuery rejects ambiguous transport input before application validation.
func parseIncidentQuery(raw string) (overview.IncidentQuery, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return overview.IncidentQuery{}, err
	}

	query := overview.IncidentQuery{}
	for key, entries := range values {
		if len(entries) != 1 {
			return overview.IncidentQuery{}, errors.New("duplicate incident selector")
		}
		switch key {
		case "before-id":
			query.BeforeID, err = strconv.ParseInt(entries[0], 10, 64)
			if err != nil || query.BeforeID < 1 {
				return overview.IncidentQuery{}, errors.New("invalid incident cursor")
			}
		case "rule":
			query.Rule = entries[0]
		case "kind":
			query.Kind = entries[0]
		default:
			return overview.IncidentQuery{}, errors.New("unsupported incident selector")
		}
	}
	return query, nil
}
