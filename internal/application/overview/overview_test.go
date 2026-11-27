package overview

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// queryStore records requested bounds and filters independently of the database.
type queryStore struct {
	bounds      Query
	ip          string
	state       model.DecisionState
	status      model.DeliveryStatus
	destination string
}

func (s *queryStore) ListRevisions(_ context.Context, q Query, ip string, state model.DecisionState) (model.RevisionPage, error) {
	s.bounds, s.ip, s.state = q, ip, state
	return model.RevisionPage{Items: []model.Revision{}, Page: q.Page}, nil
}
func (s *queryStore) ListDeliveries(_ context.Context, q Query, status model.DeliveryStatus, destination string) (model.DeliveryOverviewPage, error) {
	s.bounds, s.status, s.destination = q, status, destination
	return model.DeliveryOverviewPage{Items: []model.DeliveryOverview{}, Page: q.Page}, nil
}

func TestValidation(t *testing.T) {
	t.Parallel()
	t.Run("normalizes mapped addresses", func(t *testing.T) {
		t.Parallel()
		store := &queryStore{}
		service, err := NewService(store)
		require.NoError(t, err)
		_, err = service.Revisions(t.Context(), 2, "::ffff:203.0.113.12", model.DecisionBanned)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.12", store.ip)
		assert.Equal(t, 20, int(store.bounds.Offset))
	})
	t.Run("rejects a negative history sequence", func(t *testing.T) {
		t.Parallel()
		service, err := NewService(&queryStore{})
		require.NoError(t, err)
		_, err = service.RevisionsThrough(t.Context(), 1, "", "", -1)
		require.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("rejects invalid decision state", func(t *testing.T) {
		t.Parallel()
		service, err := NewService(&queryStore{})
		require.NoError(t, err)
		_, err = service.Revisions(t.Context(), 1, "", "unknown")
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("rejects invalid page before database access", func(t *testing.T) {
		t.Parallel()
		service, err := NewService(&queryStore{})
		require.NoError(t, err)
		_, err = service.Deliveries(t.Context(), 0, "", "")
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("rejects superseded in a current-delivery query", func(t *testing.T) {
		t.Parallel()
		service, err := NewService(&queryStore{})
		require.NoError(t, err)
		_, err = service.Deliveries(t.Context(), 1, model.DeliverySuperseded, "")
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("rejects invalid delivery state", func(t *testing.T) {
		t.Parallel()
		service, err := NewService(&queryStore{})
		require.NoError(t, err)
		_, err = service.Deliveries(t.Context(), 1, "invalid", "")
		require.ErrorIs(t, err, ErrInvalid)
	})
}

func (s *queryStore) DestinationHealth(context.Context) ([]model.DestinationHealth, error) {
	return nil, nil
}
func (s *queryStore) Timeline(context.Context, string, Query) (model.TimelinePage, error) {
	return model.TimelinePage{}, nil
}
func (s *queryStore) Incidents(context.Context, IncidentQuery) (model.IncidentPage, error) {
	return model.IncidentPage{}, nil
}
