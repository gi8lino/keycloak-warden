package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// DeliveryHealth returns aggregate counts across current delivery revisions.
func (c *Client) DeliveryHealth(ctx context.Context) ([]model.DestinationHealth, error) {
	var result []model.DestinationHealth
	err := c.do(ctx, http.MethodGet, "/deliveries/health", nil, &result)
	return result, err
}

// DecisionTimeline reads one bounded page of recorded decision activity.
func (c *Client) DecisionTimeline(ctx context.Context, id string, page int) (model.TimelinePage, error) {
	if !validDecisionID(id) || page < 1 {
		return model.TimelinePage{}, errors.New("invalid timeline selector")
	}

	var result model.TimelinePage

	err := c.do(ctx, http.MethodGet, "/bans/"+url.PathEscape(id)+"/timeline?page="+strconv.Itoa(page), nil, &result)

	return result, err
}

// validDecisionID reports whether the ID is safe to use as a URL path segment.
func validDecisionID(id string) bool {
	return id != "" &&
		id != "." &&
		id != ".." &&
		len(id) <= 128 &&
		!strings.ContainsAny(id, "/%\\?#")
}

// RetryDelivery queues one exhausted delivery without revising its decision.
func (c *Client) RetryDelivery(ctx context.Context, request model.RetryRequest) error {
	var result model.RetryResponse
	return c.do(ctx, http.MethodPost, "/deliveries/retry", request, &result)
}

// IncidentFilter selects a page of incidents.
type IncidentFilter struct {
	// BeforeID is the previous page's exclusive cursor, or zero for the first page.
	BeforeID int64
	// Rule optionally filters by detection rule name.
	Rule string
	// Kind optionally filters by event category.
	Kind string
}

// ListIncidents reads a stable page of named rule threshold hits.
func (c *Client) ListIncidents(ctx context.Context, filter IncidentFilter) (model.IncidentPage, error) {
	if filter.BeforeID < 0 {
		return model.IncidentPage{}, errors.New("invalid incident cursor")
	}
	values := url.Values{}
	if filter.BeforeID > 0 {
		values.Set("before-id", strconv.FormatInt(filter.BeforeID, 10))
	}
	if filter.Rule != "" {
		values.Set("rule", filter.Rule)
	}
	if filter.Kind != "" {
		values.Set("kind", filter.Kind)
	}
	var result model.IncidentPage
	err := c.do(ctx, http.MethodGet, "/incidents?"+values.Encode(), nil, &result)
	return result, err
}
