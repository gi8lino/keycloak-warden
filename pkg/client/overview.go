package client

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// RevisionFilter selects an optional exact IP address and desired state.
type RevisionFilter struct {
	// Page selects a one-based page; zero defaults to page one.
	Page int
	// IP optionally restricts results to one exact canonical address.
	IP string
	// State optionally restricts results to banned or unbanned events.
	State model.DecisionState
	// ThroughSequence pins this page to the first response's journal boundary.
	ThroughSequence int64
}

// DeliveryFilter selects optional current delivery status and destination.
type DeliveryFilter struct {
	// Page selects a one-based page; zero defaults to page one.
	Page int
	// Status optionally restricts results to one delivery lifecycle state.
	Status model.DeliveryStatus
	// Destination optionally restricts results to one configured target.
	Destination string
}

// ListDecisionHistory returns persisted revisions, including released decisions.
func (c *Client) ListDecisionHistory(ctx context.Context, filter RevisionFilter) (model.RevisionPage, error) {
	if filter.Page == 0 {
		filter.Page = 1
	}

	if filter.Page < 1 {
		return model.RevisionPage{}, errors.New("page must be positive")
	}

	if filter.ThroughSequence < 0 {
		return model.RevisionPage{}, errors.New("invalid history sequence")
	}

	if filter.State != "" && !filter.State.Valid() {
		return model.RevisionPage{}, errors.New("invalid state")
	}

	query := url.Values{
		"page": {
			strconv.Itoa(filter.Page),
		},
	}

	if filter.IP != "" {
		ip, err := netip.ParseAddr(filter.IP)
		if err != nil {
			return model.RevisionPage{}, errors.New("invalid IP address")
		}
		query.Set("ip", ip.Unmap().String())
	}

	if filter.State != "" {
		query.Set("state", string(filter.State))
	}
	if filter.ThroughSequence > 0 {
		query.Set("through-sequence", strconv.FormatInt(filter.ThroughSequence, 10))
	}

	var result model.RevisionPage
	err := c.do(ctx, http.MethodGet, "/decisions/history?"+query.Encode(), nil, &result)

	return result, err
}

// ListDeliveries returns current-revision progress, including unban delivery failures.
func (c *Client) ListDeliveries(ctx context.Context, filter DeliveryFilter) (model.DeliveryOverviewPage, error) {
	if filter.Page == 0 {
		filter.Page = 1
	}

	if filter.Page < 1 {
		return model.DeliveryOverviewPage{}, errors.New("page must be positive")
	}

	if filter.Status != "" && !filter.Status.Current() {
		return model.DeliveryOverviewPage{}, errors.New("invalid status")
	}

	if len(filter.Destination) > 128 || strings.ContainsAny(filter.Destination, "\x00\r\n\t") {
		return model.DeliveryOverviewPage{}, errors.New("invalid destination")
	}

	query := url.Values{
		`page`: {
			strconv.Itoa(filter.Page),
		},
	}

	if filter.Status != "" {
		query.Set("status", string(filter.Status))
	}

	if filter.Destination != "" {
		query.Set("destination", filter.Destination)
	}

	var result model.DeliveryOverviewPage
	err := c.do(ctx, http.MethodGet, "/deliveries?"+query.Encode(), nil, &result)
	return result, err
}
