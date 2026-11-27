package client

import (
	"context"
	"errors"
	"net/http"
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

	err := c.do(ctx, http.MethodGet, "/bans/"+id+"/timeline?page="+strconv.Itoa(page), nil, &result)

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

// ListObservations reads hypothetical automatic ban outcomes.
func (c *Client) ListObservations(ctx context.Context, page int) (model.ObservationPage, error) {
	if page < 1 {
		return model.ObservationPage{}, errors.New("invalid observation page")
	}
	var result model.ObservationPage
	err := c.do(ctx, http.MethodGet, "/observations?page="+strconv.Itoa(page), nil, &result)
	return result, err
}

// RetryDelivery queues one exhausted delivery without revising its decision.
func (c *Client) RetryDelivery(ctx context.Context, request model.RetryRequest) error {
	var result model.RetryResponse
	return c.do(ctx, http.MethodPost, "/deliveries/retry", request, &result)
}
