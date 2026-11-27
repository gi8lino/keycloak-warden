package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

const (
	// pageParam selects the requested result page.
	pageParam = "page"
	// ipParam filters results by IP address.
	ipParam = "ip"
	// stateParam filters results by decision state.
	stateParam = "state"
	// statusParam filters results by delivery status.
	statusParam = "status"
	// destinationParam filters results by delivery destination.
	destinationParam = "destination"
	// throughSequenceParam bounds history results to a specific sequence.
	throughSequenceParam = "through-sequence"
)

// OverviewQueries exposes cross-decision history and reconciliation status.
type OverviewQueries interface {
	RevisionsThrough(context.Context, int, string, model.DecisionState, int64) (overview.RevisionPage, error)
	Deliveries(context.Context, int, model.DeliveryStatus, string) (overview.DeliveryPage, error)
}

// DecisionHistory returns a bounded journal of effective ban and release revisions.
func DecisionHistory(service OverviewQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		values, page, ok := overviewQuery(w, r, ipParam, stateParam, throughSequenceParam)
		if !ok {
			return
		}

		through := int64(0)
		if value := values.Get(throughSequenceParam); value != "" {
			parsed, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || parsed < 1 {
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid history sequence.")
				return
			}
			through = parsed
		}

		list, err := service.RevisionsThrough(r.Context(), page, values.Get(ipParam), model.DecisionState(values.Get(stateParam)), through)
		if writeOverviewError(w, logger, err) {
			return
		}

		httpresponse.Respond(w, http.StatusOK, list)
	}
}

// DeliveryOverview returns current revision progress across all decisions.
func DeliveryOverview(service OverviewQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		values, page, ok := overviewQuery(w, r, statusParam, destinationParam)
		if !ok {
			return
		}

		list, err := service.Deliveries(r.Context(), page, model.DeliveryStatus(values.Get(statusParam)), values.Get(destinationParam))
		if writeOverviewError(w, logger, err) {
			return
		}

		httpresponse.Respond(w, http.StatusOK, list)
	}
}

// overviewQuery rejects duplicates, unknown keys, and invalid page numbers.
func overviewQuery(w http.ResponseWriter, r *http.Request, allowed ...string) (url.Values, int, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		httpresponse.Problem(w, http.StatusBadRequest, "Invalid overview query.")
		return nil, 0, false
	}

	page := 1
	for key, entries := range values {
		if len(entries) != 1 {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid overview query.")
			return nil, 0, false
		}

		if key == pageParam {
			page, err = strconv.Atoi(entries[0])
			if err != nil || page < 1 {
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid page.")
				return nil, 0, false
			}
			continue
		}

		if !slices.Contains(allowed, key) {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid overview query.")
			return nil, 0, false
		}

	}
	return values, page, true
}

// writeOverviewError never exposes private storage diagnostics to browsers.
func writeOverviewError(w http.ResponseWriter, logger *slog.Logger, err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, overview.ErrInvalid) {
		httpresponse.Problem(w, http.StatusBadRequest, err.Error())
		return true
	}

	logger.Error("overview query failed",
		"event", "overview_query_failed",
		"error", err,
	)

	httpresponse.Problem(w, http.StatusServiceUnavailable, "Administrative overview unavailable.")
	return true
}
