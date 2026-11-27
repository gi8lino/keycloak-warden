package overview

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// OperationsStore provides read-only operational projections.
type OperationsStore interface {
	// DestinationHealth returns counts across all persisted current revisions.
	DestinationHealth(context.Context) ([]model.DestinationHealth, error)
	// Timeline reads recorded activity for one decision.
	Timeline(context.Context, string, Query) (model.TimelinePage, error)
	// Observations reads hypothetical automatic ban outcomes.
	Observations(context.Context, Query) (model.ObservationPage, error)
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
func (s *Operations) Health(ctx context.Context) ([]model.DestinationHealth, error) {
	return s.store.DestinationHealth(ctx)
}

// Timeline returns a bounded chronology for a stable decision identifier.
func (s *Operations) Timeline(ctx context.Context, id string, page int) (model.TimelinePage, error) {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return model.TimelinePage{}, fmt.Errorf("%w: invalid decision ID", ErrInvalid)
	}

	bounds, err := NewQuery(page)
	if err != nil {
		return model.TimelinePage{}, err
	}

	return s.store.Timeline(ctx, id, bounds)
}

// Observations returns bounded observe-only results.
func (s *Operations) Observations(ctx context.Context, page int) (model.ObservationPage, error) {
	bounds, err := NewQuery(page)
	if err != nil {
		return model.ObservationPage{}, err
	}
	return s.store.Observations(ctx, bounds)
}

// ErrTimelineNotFound identifies a missing decision.
var ErrTimelineNotFound = bans.ErrNotFound
