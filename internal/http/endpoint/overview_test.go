package endpoint_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
)

// overviewStub captures validated selectors passed to the application.
type overviewStub struct {
	page        int
	ip          string
	state       decisionstate.State
	status      deliverystate.Status
	destination string
}

func (s *overviewStub) Revisions(_ context.Context, page int, ip string, state decisionstate.State) (overview.RevisionPage, error) {
	s.page, s.ip, s.state = page, ip, state
	return overview.RevisionPage{Items: []overview.Revision{}, Page: page}, nil
}

func (s *overviewStub) Deliveries(_ context.Context, page int, status deliverystate.Status, destination string) (overview.DeliveryPage, error) {
	s.page, s.status, s.destination = page, status, destination
	return overview.DeliveryPage{Items: []overview.Delivery{}, Page: page}, nil
}

func TestOverviewEndpoints(t *testing.T) {
	t.Parallel()

	t.Run("returns filtered decision revisions", func(t *testing.T) {
		t.Parallel()
		service := &overviewStub{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		response := httptest.NewRecorder()
		endpoint.DecisionHistory(service, logger)(response, httptest.NewRequest(http.MethodGet, "/decisions/history?page=2&ip=203.0.113.42&state=unbanned", nil))
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, 2, service.page)
		assert.Equal(t, "203.0.113.42", service.ip)
		assert.Equal(t, decisionstate.StateUnbanned, service.state)
		require.Contains(t, response.Body.String(), `"page":2`)
	})

	t.Run("returns filtered deliveries", func(t *testing.T) {
		t.Parallel()
		service := &overviewStub{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		response := httptest.NewRecorder()
		endpoint.DeliveryOverview(service, logger)(response, httptest.NewRequest(http.MethodGet, "/deliveries?status=exhausted&destination=edge", nil))
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, deliverystate.StatusExhausted, service.status)
		assert.Equal(t, "edge", service.destination)
	})

	t.Run("rejects duplicate query parameters", func(t *testing.T) {
		t.Parallel()
		service := &overviewStub{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		response := httptest.NewRecorder()
		endpoint.DecisionHistory(service, logger)(response, httptest.NewRequest(http.MethodGet, "/decisions/history?page=1&page=2", nil))
		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.page)
	})

	t.Run("rejects unknown selectors", func(t *testing.T) {
		t.Parallel()
		service := &overviewStub{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		response := httptest.NewRecorder()
		endpoint.DeliveryOverview(service, logger)(response, httptest.NewRequest(http.MethodGet, "/deliveries?unexpected=true", nil))
		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.page)
	})
}
