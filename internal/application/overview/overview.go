// Package overview defines bounded, read-only administration queries across decisions.
package overview

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
	"github.com/gi8lino/keycloak-warden/pkg/model"
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

// Store performs the read-only queries in one SQLite snapshot per call.
type Store interface {
	// ListRevisions retrieves a bounded page of immutable decision changes.
	ListRevisions(context.Context, Query, string, model.DecisionState) (model.RevisionPage, error)
	// ListDeliveries retrieves only the latest destination revision per decision.
	ListDeliveries(context.Context, Query, model.DeliveryStatus, string) (model.DeliveryOverviewPage, error)
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
func (s *Service) Revisions(ctx context.Context, page int, ip string, state model.DecisionState) (model.RevisionPage, error) {
	return s.RevisionsThrough(ctx, page, ip, state, 0)
}

// RevisionsThrough pins numbered pages to the original journal insertion boundary.
func (s *Service) RevisionsThrough(
	ctx context.Context,
	page int,
	ip string,
	state model.DecisionState,
	through int64,
) (model.RevisionPage, error) {
	if through < 0 {
		return model.RevisionPage{}, fmt.Errorf("%w: invalid history sequence", ErrInvalid)
	}

	bounds, err := NewQuery(page)
	if err != nil {
		return model.RevisionPage{}, err
	}

	if state != "" && !state.Valid() {
		return model.RevisionPage{}, fmt.Errorf("%w: unsupported decision state", ErrInvalid)
	}

	if ip != "" {
		address, err := ipaddress.ParseUnicast(strings.TrimSpace(ip))
		if err != nil {
			return model.RevisionPage{}, fmt.Errorf("%w: invalid IP address", ErrInvalid)
		}
		ip = address.Unmap().String()
	}

	bounds.ThroughSequence = through
	return s.store.ListRevisions(ctx, bounds, ip, state)
}

// Deliveries returns current-revision destination progress, including failed releases.
func (s *Service) Deliveries(ctx context.Context, page int, status model.DeliveryStatus, destination string) (model.DeliveryOverviewPage, error) {
	bounds, err := NewQuery(page)
	if err != nil {
		return model.DeliveryOverviewPage{}, err
	}

	if status != "" && !status.Current() {
		return model.DeliveryOverviewPage{}, fmt.Errorf("%w: unsupported delivery status", ErrInvalid)
	}

	if len(destination) > MaxDestinationLength ||
		strings.TrimSpace(destination) != destination ||
		strings.ContainsAny(destination, "\x00\r\n\t") {
		return model.DeliveryOverviewPage{}, fmt.Errorf("%w: invalid destination", ErrInvalid)
	}

	return s.store.ListDeliveries(ctx, bounds, status, destination)
}
