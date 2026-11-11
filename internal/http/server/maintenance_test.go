package server_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
)

// testMaintenance responds to maintenance API requests without a database.
type testMaintenance struct{}

// Snapshot returns a predictable test status.
func (testMaintenance) Snapshot() maintenance.Status { return maintenance.Status{} }

// Trigger accepts an administrative maintenance request.
func (testMaintenance) Trigger(context.Context, maintenance.Operation) error { return nil }

// assertMaintenanceRoute verifies one independently configured HTTP route.
func assertMaintenanceRoute(t *testing.T, method, path, token, provided string, want int) {
	t.Helper()

	handlers := server.New(server.Config{
		AdminToken:  token,
		Maintenance: testMaintenance{},
		Logger:      slog.Default(),
	})

	request := httptest.NewRequest(method, path, nil)
	if provided != "" {
		request.Header.Set("Authorization", "Bearer "+provided)
	}

	response := httptest.NewRecorder()
	handlers.Application.ServeHTTP(response, request)

	assert.Equal(t, want, response.Code)
}

func TestMaintenanceRouteAuth(t *testing.T) {
	t.Parallel()

	t.Run("status route disabled without admin token", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodGet, "/maintenance", "", "", http.StatusNotFound)
	})

	t.Run("prune route disabled without admin token", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/prune", "", "", http.StatusNotFound)
	})

	t.Run("optimize route disabled without admin token", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/optimize", "", "", http.StatusNotFound)
	})

	t.Run("status rejects missing credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodGet, "/maintenance", "admin", "", http.StatusUnauthorized)
	})

	t.Run("prune rejects missing credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/prune", "admin", "", http.StatusUnauthorized)
	})

	t.Run("optimize rejects missing credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/optimize", "admin", "", http.StatusUnauthorized)
	})

	t.Run("status rejects invalid credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodGet, "/maintenance", "admin", "wrong", http.StatusUnauthorized)
	})

	t.Run("prune rejects invalid credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/prune", "admin", "wrong", http.StatusUnauthorized)
	})

	t.Run("optimize rejects invalid credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/optimize", "admin", "wrong", http.StatusUnauthorized)
	})

	t.Run("status accepts valid credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodGet, "/maintenance", "admin", "admin", http.StatusOK)
	})

	t.Run("prune accepts valid credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/prune", "admin", "admin", http.StatusOK)
	})

	t.Run("optimize accepts valid credential", func(t *testing.T) {
		t.Parallel()

		assertMaintenanceRoute(t, http.MethodPost, "/maintenance/optimize", "admin", "admin", http.StatusOK)
	})
}
