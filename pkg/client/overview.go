package client

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
)

// Revision is an immutable decision change, including sources at the time of change.
type Revision struct {
	// DecisionID identifies the stable decision that owns this revision.
	DecisionID string `json:"decisionId"`
	// IPAddress is the canonical address that the decision concerns.
	IPAddress string `json:"ipAddress"`
	// Revision is the monotonically increasing decision version.
	Revision int64 `json:"revision"`
	// State is the desired blocking state recorded at this revision.
	State decisionstate.State `json:"state"`
	// Cause identifies the workflow that created this revision.
	Cause string `json:"cause"`
	// ExpiresAt is the deadline recorded for this decision revision.
	ExpiresAt time.Time `json:"expiresAt"`
	// ChangedAt is when the transaction committed this revision.
	ChangedAt time.Time `json:"changedAt"`
	// Sources contains the reasons that were active at this revision.
	Sources []Source `json:"sources"`
}

// RevisionPage is one bounded page of effective decision changes.
type RevisionPage struct {
	// Items contains the selected immutable decision revisions.
	Items []Revision `json:"items"`
	// Page identifies this one-based page.
	Page int `json:"page"`
	// NextPage is the next older page, or zero when the page is final.
	NextPage int `json:"nextPage,omitempty"`
}

// DeliveryOverview describes a destination's progress on a decision's current revision.
type DeliveryOverview struct {
	// DecisionID identifies the decision associated with this destination.
	DecisionID string `json:"decisionId"`
	// IPAddress is the canonical decision address.
	IPAddress string `json:"ipAddress"`
	// Revision identifies the current desired decision version.
	Revision int64 `json:"revision"`
	// DesiredState is the latest state requested by Warden.
	DesiredState decisionstate.State `json:"desiredState"`
	// Destination is the configured target identifier.
	Destination string `json:"destination"`
	// Status is the current revision delivery lifecycle.
	Status deliverystate.Status `json:"status"`
	// AcknowledgedRevision is the last accepted version, or zero when absent.
	AcknowledgedRevision int64 `json:"acknowledgedRevision"`
	// AttemptCount is the number of completed current-revision attempts.
	AttemptCount int64 `json:"attemptCount"`
	// ChangedAt is the decision revision commit time when known.
	ChangedAt *time.Time `json:"changedAt,omitempty"`
	// LastAttemptAt is the latest completed provider call time.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
	// NextAttemptAt is the next scheduled retry when applicable.
	NextAttemptAt *time.Time `json:"nextAttemptAt,omitempty"`
	// LastError is a bounded diagnostic from the latest provider call.
	LastError string `json:"lastError,omitempty"`
}

// DeliveryOverviewPage is one bounded page of current destination progress.
type DeliveryOverviewPage struct {
	// Items contains the selected current-revision destination entries.
	Items []DeliveryOverview `json:"items"`
	// Page identifies this one-based page.
	Page int `json:"page"`
	// NextPage is the next older page, or zero when the page is final.
	NextPage int `json:"nextPage,omitempty"`
}

// RevisionFilter selects an optional exact IP address and desired state.
type RevisionFilter struct {
	// Page selects a one-based page; zero defaults to page one.
	Page int
	// IP optionally restricts results to one exact canonical address.
	IP string
	// State optionally restricts results to banned or unbanned events.
	State decisionstate.State
}

// DeliveryFilter selects optional current delivery status and destination.
type DeliveryFilter struct {
	// Page selects a one-based page; zero defaults to page one.
	Page int
	// Status optionally restricts results to one delivery lifecycle state.
	Status deliverystate.Status
	// Destination optionally restricts results to one configured target.
	Destination string
}

// ListDecisionHistory returns persisted revisions, including released decisions.
func (c *Client) ListDecisionHistory(ctx context.Context, filter RevisionFilter) (RevisionPage, error) {
	if filter.Page == 0 {
		filter.Page = 1
	}

	if filter.Page < 1 {
		return RevisionPage{}, errors.New("page must be positive")
	}

	if filter.State != "" && !filter.State.Valid() {
		return RevisionPage{}, errors.New("invalid state")
	}

	query := url.Values{
		"page": {
			strconv.Itoa(filter.Page),
		},
	}

	if filter.IP != "" {
		ip, err := netip.ParseAddr(filter.IP)
		if err != nil {
			return RevisionPage{}, errors.New("invalid IP address")
		}
		query.Set("ip", ip.Unmap().String())
	}

	if filter.State != "" {
		query.Set("state", string(filter.State))
	}

	var result RevisionPage
	err := c.do(ctx, http.MethodGet, "/decisions/history?"+query.Encode(), nil, &result)

	return result, err
}

// ListDeliveries returns current-revision progress, including unban delivery failures.
func (c *Client) ListDeliveries(ctx context.Context, filter DeliveryFilter) (DeliveryOverviewPage, error) {
	if filter.Page == 0 {
		filter.Page = 1
	}

	if filter.Page < 1 {
		return DeliveryOverviewPage{}, errors.New("page must be positive")
	}

	if filter.Status != "" && !filter.Status.Current() {
		return DeliveryOverviewPage{}, errors.New("invalid status")
	}

	if len(filter.Destination) > 128 || strings.ContainsAny(filter.Destination, "\x00\r\n\t") {
		return DeliveryOverviewPage{}, errors.New("invalid destination")
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

	var result DeliveryOverviewPage
	err := c.do(ctx, http.MethodGet, "/deliveries?"+query.Encode(), nil, &result)
	return result, err
}
