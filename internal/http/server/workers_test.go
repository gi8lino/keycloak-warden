package server_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/workers"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/maintenance"
	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// testWorkerStatus supplies deterministic worker state without opening SQLite.
type testWorkerStatus struct {
	// err simulates a worker snapshot failure.
	err error
}

// Snapshot provides one sample action and maintenance worker report.
func (s testWorkerStatus) Snapshot(context.Context) (workers.Status, error) {
	if s.err != nil {
		return workers.Status{}, s.err
	}
	return workers.Status{
		Actions: workers.Actions{
			RuntimeStatus: actions.RuntimeStatus{
				State:     workerstate.StateIdle,
				StartedAt: time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC),
			},
			QueueStats: workers.QueueStats{
				PendingDeliveries: 2,
			},
		},
		Maintenance: maintenance.Status{
			State: workerstate.StateIdle,
		},
	}, nil
}

// TestWorkersRoute verifies admin authentication and the serialized status contract.
func TestWorkersRoute(t *testing.T) {
	t.Parallel()

	t.Run("disabled without an admin token", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			Workers: testWorkerStatus{},
			Logger:  slog.Default(),
		})
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/workers", nil))

		assert.Equal(t, http.StatusNotFound, response.Code)
	})

	t.Run("rejects anonymous requests", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken: "secret",
			Workers:    testWorkerStatus{},
			Logger:     slog.Default(),
		})
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/workers", nil))

		assert.Equal(t, http.StatusUnauthorized, response.Code)
	})

	t.Run("returns both workers to an administrator", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken: "secret",
			Workers:    testWorkerStatus{},
			Logger:     slog.Default(),
		})
		request := httptest.NewRequest(http.MethodGet, "/workers", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		assert.Contains(t, response.Body.String(), `"pendingDeliveries":2`)
		assert.Contains(t, response.Body.String(), `"maintenance"`)
		assert.Contains(t, response.Body.String(), `"state":"idle"`)
	})

	t.Run("respects the application route prefix", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken:  "secret",
			RoutePrefix: "/warden",
			Workers:     testWorkerStatus{},
			Logger:      slog.Default(),
		})
		request := httptest.NewRequest(http.MethodGet, "/warden/workers", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, request)

		assert.Equal(t, http.StatusOK, response.Code)
	})

	t.Run("does not reveal storage errors", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken: "secret",
			Workers:    testWorkerStatus{err: errors.New("private database diagnostic")},
			Logger:     slog.Default(),
		})
		request := httptest.NewRequest(http.MethodGet, "/workers", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, request)

		assert.Equal(t, http.StatusInternalServerError, response.Code)
		assert.NotContains(t, response.Body.String(), "private database diagnostic")
	})
}
