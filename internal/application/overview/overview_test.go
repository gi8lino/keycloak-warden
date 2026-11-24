package overview

import (
	"context"
	"testing"

	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queryStore records requested bounds and filters independently of the database.
type queryStore struct {
	bounds      Query
	ip          string
	state       decisionstate.State
	status      deliverystate.Status
	destination string
}

func (s *queryStore) ListRevisions(_ context.Context, q Query, ip string, state decisionstate.State) (RevisionPage, error) {
	s.bounds, s.ip, s.state = q, ip, state
	return RevisionPage{Items: []Revision{}, Page: q.Page}, nil
}
func (s *queryStore) ListDeliveries(_ context.Context, q Query, status deliverystate.Status, destination string) (DeliveryPage, error) {
	s.bounds, s.status, s.destination = q, status, destination
	return DeliveryPage{Items: []Delivery{}, Page: q.Page}, nil
}

func TestValidation(t *testing.T) {
	t.Parallel()
	t.Run("normalizes mapped addresses", func(t *testing.T) {
		t.Parallel()
		store := &queryStore{}
		service, err := NewService(store)
		require.NoError(t, err)
		_, err = service.Revisions(t.Context(), 2, "::ffff:203.0.113.12", decisionstate.StateBanned)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.12", store.ip)
		assert.Equal(t, 20, int(store.bounds.Offset))
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
	t.Run("rejects invalid delivery state", func(t *testing.T) {
		t.Parallel()
		service, err := NewService(&queryStore{})
		require.NoError(t, err)
		_, err = service.Deliveries(t.Context(), 1, "invalid", "")
		require.ErrorIs(t, err, ErrInvalid)
	})
}
