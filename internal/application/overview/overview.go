// Package overview defines bounded, read-only administration queries across decisions.
package overview

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
)

const (
	// PageSize limits each cross-decision administrative query.
	PageSize = 20
	// MaxDestinationLength bounds the provider identifier accepted as a filter.
	MaxDestinationLength = 128
)

// ErrInvalid identifies unsupported or unbounded listing filters.
var ErrInvalid = errors.New("invalid overview query")

// Query contains validated SQL pagination bounds.
type Query struct {
	// Page is the one-based page requested by the caller.
	Page int
	// Offset skips older rows.
	Offset int64
	// Limit is the maximum number of entries in the response.
	Limit int
	// ThroughSequence pins the newest journal entry visible across all pages.
	ThroughSequence int64
}

// NewQuery validates offset calculations before database access.
func NewQuery(page int) (Query, error) {
	if page < 1 || int64(page-1) > math.MaxInt64/PageSize {
		return Query{}, fmt.Errorf("%w: page must be positive and within range", ErrInvalid)
	}
	return Query{Page: page, Offset: int64(page-1) * PageSize, Limit: PageSize}, nil
}

// Revision is one immutable snapshot of a changed desired decision.
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
	Cause bans.ChangeCause `json:"cause"`
	// ExpiresAt is the deadline recorded for this decision revision.
	ExpiresAt time.Time `json:"expiresAt"`
	// ChangedAt is when the transaction committed this revision.
	ChangedAt time.Time `json:"changedAt"`
	// Sources contains the reasons that were active at this revision.
	Sources []bans.Source `json:"sources"`
}

// RevisionPage contains bounded, newest-first decision changes.
type RevisionPage struct {
	// Items contains the selected immutable decision revisions.
	Items []Revision `json:"items"`
	// Page identifies this one-based page.
	Page int `json:"page"`
	// NextPage is the next older page, or zero when the page is final.
	NextPage int `json:"nextPage,omitempty"`
	// ThroughSequence anchors future pages to the same journal membership.
	ThroughSequence int64 `json:"throughSequence,omitempty"`
}

// Delivery is the current revision's progress for one destination and decision.
type Delivery struct {
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

// DeliveryPage contains bounded current-state reconciliation entries.
type DeliveryPage struct {
	// Items contains the selected current-revision destination entries.
	Items []Delivery `json:"items"`
	// Page identifies this one-based page.
	Page int `json:"page"`
	// NextPage is the next older page, or zero when the page is final.
	NextPage int `json:"nextPage,omitempty"`
}

// Store performs the read-only queries in one SQLite snapshot per call.
type Store interface {
	// ListRevisions retrieves a bounded page of immutable decision changes.
	ListRevisions(context.Context, Query, string, decisionstate.State) (RevisionPage, error)
	// ListDeliveries retrieves only the latest destination revision per decision.
	ListDeliveries(context.Context, Query, deliverystate.Status, string) (DeliveryPage, error)
}

// Service validates and executes administrative queries.
type Service struct {
	// store is the read-only persistence capability used by these queries.
	store Store
}

// NewService constructs a cross-decision query service.
func NewService(store Store) (*Service, error) {
	if store == nil {
		return nil, errors.New("overview store is required")
	}
	return &Service{store: store}, nil
}

// Revisions returns immutable decision transitions, including releases and extensions.
func (s *Service) Revisions(ctx context.Context, page int, ip string, state decisionstate.State) (RevisionPage, error) {
	return s.RevisionsThrough(ctx, page, ip, state, 0)
}

// RevisionsThrough pins numbered pages to the original journal insertion boundary.
func (s *Service) RevisionsThrough(
	ctx context.Context,
	page int,
	ip string,
	state decisionstate.State,
	through int64,
) (RevisionPage, error) {
	if through < 0 {
		return RevisionPage{}, fmt.Errorf("%w: invalid history sequence", ErrInvalid)
	}

	bounds, err := NewQuery(page)
	if err != nil {
		return RevisionPage{}, err
	}

	if state != "" && !state.Valid() {
		return RevisionPage{}, fmt.Errorf("%w: unsupported decision state", ErrInvalid)
	}

	if ip != "" {
		address, err := ipaddress.ParseUnicast(strings.TrimSpace(ip))
		if err != nil {
			return RevisionPage{}, fmt.Errorf("%w: invalid IP address", ErrInvalid)
		}
		ip = address.Unmap().String()
	}

	bounds.ThroughSequence = through
	return s.store.ListRevisions(ctx, bounds, ip, state)
}

// Deliveries returns current-revision destination progress, including failed releases.
func (s *Service) Deliveries(ctx context.Context, page int, status deliverystate.Status, destination string) (DeliveryPage, error) {
	bounds, err := NewQuery(page)
	if err != nil {
		return DeliveryPage{}, err
	}

	if status != "" && !status.Current() {
		return DeliveryPage{}, fmt.Errorf("%w: unsupported delivery status", ErrInvalid)
	}

	if len(destination) > MaxDestinationLength ||
		strings.TrimSpace(destination) != destination ||
		strings.ContainsAny(destination, "\x00\r\n\t") {
		return DeliveryPage{}, fmt.Errorf("%w: invalid destination", ErrInvalid)
	}

	return s.store.ListDeliveries(ctx, bounds, status, destination)
}
