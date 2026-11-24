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
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
)

const (
	pageParam        = "page"
	ipParam          = "ip"
	stateParam       = "state"
	statusParam      = "status"
	destinationParam = "destination"
)

// OverviewQueries exposes cross-decision history and reconciliation status.
type OverviewQueries interface {
	Revisions(context.Context, int, string, decisionstate.State) (overview.RevisionPage, error)
	Deliveries(context.Context, int, deliverystate.Status, string) (overview.DeliveryPage, error)
}

// DecisionHistory returns a bounded journal of effective ban and release revisions.
func DecisionHistory(service OverviewQueries, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		values, page, ok := overviewQuery(w, r, ipParam, stateParam)
		if !ok {
			return
		}

		list, err := service.Revisions(r.Context(), page, values.Get(ipParam), decisionstate.State(values.Get(stateParam)))
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

		list, err := service.Deliveries(r.Context(), page, deliverystate.Status(values.Get(statusParam)), values.Get(destinationParam))
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
