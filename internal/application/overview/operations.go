package overview

import (
	"context"
	"fmt"
	"strings"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// OperationsStore provides read-only operational projections.
type OperationsStore interface {
	// DestinationHealth returns counts across all persisted current revisions.
	DestinationHealth(context.Context) ([]model.DestinationHealth, error)
	// Timeline reads recorded activity for one decision.
	Timeline(context.Context, string, Query) (model.TimelinePage, error)
	// Incidents reads named rule threshold hits.
	Incidents(context.Context, IncidentQuery) (model.IncidentPage, error)
}

// Health returns aggregate current delivery counts.
func (s *Service) Health(ctx context.Context) ([]model.DestinationHealth, error) {
	return s.store.DestinationHealth(ctx)
}

// Timeline returns a bounded chronology for a stable decision identifier.
func (s *Service) Timeline(ctx context.Context, id string, page int) (model.TimelinePage, error) {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return model.TimelinePage{}, fmt.Errorf("%w: invalid decision ID", ErrInvalid)
	}

	bounds, err := NewQuery(page)
	if err != nil {
		return model.TimelinePage{}, err
	}

	return s.store.Timeline(ctx, id, bounds)
}

// ErrTimelineNotFound identifies a missing decision.
var ErrTimelineNotFound = bans.ErrNotFound

// IncidentQuery selects a bounded newest-first incident page.
type IncidentQuery struct {
	// BeforeID excludes the previous page and all newer records; zero starts at the newest.
	BeforeID int64
	// Rule optionally filters the detection policy name.
	Rule string
	// Kind optionally filters the event category.
	Kind string
}

// Incidents returns recorded rule occurrences using a stable ID cursor.
func (s *Service) Incidents(ctx context.Context, query IncidentQuery) (model.IncidentPage, error) {
	if query.BeforeID < 0 || len(query.Rule) > 64 {
		return model.IncidentPage{}, fmt.Errorf("%w: invalid incident filter", ErrInvalid)
	}
	if query.Kind != "" && query.Kind != events.KindUser && query.Kind != events.KindAdmin {
		return model.IncidentPage{}, fmt.Errorf("%w: unsupported event category", ErrInvalid)
	}
	return s.store.Incidents(ctx, query)
}
