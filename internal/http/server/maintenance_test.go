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

func TestMaintenanceRouteAuth(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		token    string
		provided string
		want     int
	}{
		{name: "disabled", want: http.StatusNotFound},
		{name: "missing credential", token: "admin", want: http.StatusUnauthorized},
		{name: "invalid credential", token: "admin", provided: "wrong", want: http.StatusUnauthorized},
		{name: "authorized", token: "admin", provided: "admin", want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			handlers := server.New(server.Config{AdminToken: tc.token, Maintenance: testMaintenance{}, Logger: slog.Default()})
			for _, route := range []struct{ method, path string }{{"GET", "/maintenance"}, {"POST", "/maintenance/prune"}, {"POST", "/maintenance/optimize"}} {
				req := httptest.NewRequest(route.method, route.path, nil)
				if tc.provided != "" {
					req.Header.Set("Authorization", "Bearer "+tc.provided)
				}
				resp := httptest.NewRecorder()
				handlers.Application.ServeHTTP(resp, req)
				assert.Equal(t, tc.want, resp.Code)
			}
		})
	}
}
