package overview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// DestinationHealth aggregates current delivery states across all decisions for a destination.
type DestinationHealth struct {
	// Destination is the provider-qualified name.
	Destination string `json:"destination"`
	// Pending counts deliveries awaiting their first attempt or explicit retry.
	Pending int64 `json:"pending"`
	// Retrying counts failed deliveries scheduled to retry.
	Retrying int64 `json:"retrying"`
	// Exhausted counts failed deliveries without an automatic retry budget.
	Exhausted int64 `json:"exhausted"`
	// FailedUnbans counts retrying or exhausted releases.
	FailedUnbans int64 `json:"failedUnbans"`
	// ExhaustedUnbans counts releases requiring operator intervention.
	ExhaustedUnbans int64 `json:"exhaustedUnbans"`
	// Delivered counts acknowledged current revisions.
	Delivered int64 `json:"delivered"`
}

// TimelineEvent describes one persisted audit fact, not a synthesized event.
type TimelineEvent struct {
	// At is the recorded event timestamp.
	At time.Time `json:"at"`
	// Kind distinguishes source, decision, attempt and retry records.
	Kind string `json:"kind"`
	// Action identifies the recorded transition or outcome.
	Action string `json:"action"`
	// SourceKind identifies the affected source for source mutations.
	SourceKind string `json:"sourceKind,omitempty"`
	// State identifies the desired state for a decision revision.
	State string `json:"state,omitempty"`
	// Revision is the decision revision when known.
	Revision int64 `json:"revision,omitempty"`
	// Destination identifies the delivery target when applicable.
	Destination string `json:"destination,omitempty"`
	// Detail contains a bounded source reason or delivery error.
	Detail string `json:"detail,omitempty"`
	// Actor is the caller-asserted identity for an explicit retry.
	Actor string `json:"actor,omitempty"`
	// ExpiresAt records a source or decision deadline, not an actual release time.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// Attempt is the historical attempt number when applicable.
	Attempt int64 `json:"attempt,omitempty"`
}

// TimelinePage returns a bounded newest-first view of recorded events.
type TimelinePage struct {
	// DecisionID identifies the selected decision.
	DecisionID string `json:"decisionId"`
	// IP identifies the selected decision's address.
	IP string `json:"ipAddress"`
	// Items contains the events on this page.
	Items []TimelineEvent `json:"items"`
	// Page identifies this page.
	Page int `json:"page"`
	// NextPage identifies the next older page if present.
	NextPage int `json:"nextPage,omitempty"`
}

// ObservationPage returns recent hypothetical automatic bans.
type ObservationPage struct {
	// Items contains recorded threshold hits.
	Items []ingestion.Observation `json:"items"`
	// Page identifies this page.
	Page int `json:"page"`
	// NextPage identifies the next older page if present.
	NextPage int `json:"nextPage,omitempty"`
}

// OperationsStore provides read-only operational projections.
type OperationsStore interface {
	// DestinationHealth returns counts across all persisted current revisions.
	DestinationHealth(context.Context) ([]DestinationHealth, error)
	// Timeline reads recorded activity for one decision.
	Timeline(context.Context, string, Query) (TimelinePage, error)
	// Observations reads hypothetical automatic ban outcomes.
	Observations(context.Context, Query) (ObservationPage, error)
}

// Operations exposes operational projections with validated query bounds.
type Operations struct {
	// store reads persisted facts.
	store OperationsStore
}

// NewOperations constructs the operational read service.
func NewOperations(store OperationsStore) (*Operations, error) {
	if store == nil {
		return nil, errors.New("operations store is required")
	}
	return &Operations{store: store}, nil
}

// Health returns aggregate current delivery counts.
func (s *Operations) Health(ctx context.Context) ([]DestinationHealth, error) {
	return s.store.DestinationHealth(ctx)
}

// Timeline returns a bounded chronology for a stable decision identifier.
func (s *Operations) Timeline(ctx context.Context, id string, page int) (TimelinePage, error) {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return TimelinePage{}, fmt.Errorf("%w: invalid decision ID", ErrInvalid)
	}

	bounds, err := NewQuery(page)
	if err != nil {
		return TimelinePage{}, err
	}

	return s.store.Timeline(ctx, id, bounds)
}

// Observations returns bounded observe-only results.
func (s *Operations) Observations(ctx context.Context, page int) (ObservationPage, error) {
	bounds, err := NewQuery(page)
	if err != nil {
		return ObservationPage{}, err
	}
	return s.store.Observations(ctx, bounds)
}

// ErrTimelineNotFound identifies a missing decision.
var ErrTimelineNotFound = bans.ErrNotFound
