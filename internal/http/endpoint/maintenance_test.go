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
		response := httptest.NewRecorder()
		endpoint.MaintenanceStatus(&scriptedMaintenance{})(response, httptest.NewRequest(http.MethodGet, "/maintenance", nil))
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Contains(t, response.Body.String(), `"pruneInterval":"1h0m0s"`)
	})
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, http.StatusOK},
		{"busy", maintenance.ErrBusy, http.StatusConflict},
		{"canceled", context.Canceled, http.StatusServiceUnavailable},
		{"failure", errors.New("secret database error"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			service := &scriptedMaintenance{err: tc.err}
			response := httptest.NewRecorder()
			endpoint.RunMaintenance(service, logger, maintenance.OperationPrune)(response, httptest.NewRequest(http.MethodPost, "/maintenance/prune", nil))
			require.Equal(t, tc.want, response.Code)
			assert.Equal(t, maintenance.OperationPrune, service.called)
			if tc.err != nil {
				assert.NotContains(t, response.Body.String(), "secret database error")
			}
		})
	}
}
