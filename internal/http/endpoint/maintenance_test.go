package endpoint_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// scriptedMaintenance implements maintenance operations for HTTP adapter tests.
type scriptedMaintenance struct {
	// err is returned by Trigger.
	err error
	// called tracks manual requests.
	called maintenance.Operation
}

// Snapshot returns a known successful status.
func (s *scriptedMaintenance) Snapshot() maintenance.Status {
	return maintenance.Status{PruneInterval: "1h0m0s"}
}

// Trigger records one requested maintenance operation.
func (s *scriptedMaintenance) Trigger(_ context.Context, operation maintenance.Operation) error {
	s.called = operation
	return s.err
}

func TestMaintenanceHandlers(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("status", func(t *testing.T) {
		t.Parallel()

		service := &scriptedMaintenance{}
		request := httptest.NewRequest(http.MethodGet, "/maintenance", nil)
		response := httptest.NewRecorder()

		endpoint.MaintenanceStatus(service)(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		assert.Contains(t, response.Body.String(), `"pruneInterval":"1h0m0s"`)
	})

	t.Run("successful prune", func(t *testing.T) {
		t.Parallel()

		service := &scriptedMaintenance{}
		request := httptest.NewRequest(http.MethodPost, "/maintenance/prune", nil)
		response := httptest.NewRecorder()

		endpoint.RunMaintenance(service, logger, maintenance.OperationPrune)(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, maintenance.OperationPrune, service.called)
	})

	t.Run("busy prune", func(t *testing.T) {
		t.Parallel()

		service := &scriptedMaintenance{err: maintenance.ErrBusy}
		request := httptest.NewRequest(http.MethodPost, "/maintenance/prune", nil)
		response := httptest.NewRecorder()

		endpoint.RunMaintenance(service, logger, maintenance.OperationPrune)(response, request)

		require.Equal(t, http.StatusConflict, response.Code)
		assert.Equal(t, maintenance.OperationPrune, service.called)
	})

	t.Run("canceled prune", func(t *testing.T) {
		t.Parallel()

		service := &scriptedMaintenance{err: context.Canceled}
		request := httptest.NewRequest(http.MethodPost, "/maintenance/prune", nil)
		response := httptest.NewRecorder()

		endpoint.RunMaintenance(service, logger, maintenance.OperationPrune)(response, request)

		require.Equal(t, http.StatusServiceUnavailable, response.Code)
		assert.Equal(t, maintenance.OperationPrune, service.called)
	})

	t.Run("failed prune does not leak internal errors", func(t *testing.T) {
		t.Parallel()

		service := &scriptedMaintenance{err: errors.New("secret database error")}
		request := httptest.NewRequest(http.MethodPost, "/maintenance/prune", nil)
		response := httptest.NewRecorder()

		endpoint.RunMaintenance(service, logger, maintenance.OperationPrune)(response, request)

		require.Equal(t, http.StatusInternalServerError, response.Code)
		assert.Equal(t, maintenance.OperationPrune, service.called)
		assert.NotContains(t, response.Body.String(), "secret database error")
	})
}
