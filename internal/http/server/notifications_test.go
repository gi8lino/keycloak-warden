package server_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// notificationAPI supplies deterministic history and retry results.
type notificationAPI struct {
	// retryErr simulates rejected retry admission.
	retryErr error
}

// Deliveries returns one retained occurrence.
func (notificationAPI) Deliveries(context.Context, int64) (model.NotificationPage, error) {
	return model.NotificationPage{Items: []model.NotificationDelivery{{ID: 42}}}, nil
}

// Attempts returns the known outbound sends.
func (notificationAPI) Attempts(context.Context, int64, int64) (model.NotificationAttemptPage, error) {
	return model.NotificationAttemptPage{Items: []model.NotificationAttempt{{Number: 3}}}, nil
}

// Retry returns the configured admission outcome.
func (a notificationAPI) Retry(context.Context, int64, string, time.Time) error { return a.retryErr }

func TestNotificationRoutes(t *testing.T) {
	t.Parallel()

	t.Run("requires administrator authentication", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken:    "secret",
			Notifications: notificationAPI{},
			Logger:        slog.Default(),
		})
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/notifications", nil))

		assert.Equal(t, http.StatusUnauthorized, response.Code)
	})

	t.Run("returns retained delivery history", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken:    "secret",
			Notifications: notificationAPI{},
			Logger:        slog.Default(),
		})
		request := httptest.NewRequest(http.MethodGet, "/notifications?before-id=50", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		assert.Contains(t, response.Body.String(), `"id":42`)
	})

	t.Run("rejects duplicate attempt cursors", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken:    "secret",
			Notifications: notificationAPI{},
			Logger:        slog.Default(),
		})
		request := httptest.NewRequest(http.MethodGet, "/notifications/42/attempts?before-number=2&before-number=3", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
	})

	t.Run("rejects ineligible explicit retries", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			AdminToken:        "secret",
			NotificationRetry: notificationAPI{retryErr: notifications.ErrRetryConflict},
			Logger:            slog.Default(),
		})
		request := httptest.NewRequest(http.MethodPost, "/notifications/42/retry", strings.NewReader(`{"actor":"operator"}`))
		request.Header.Set("Authorization", "Bearer secret")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handlers.Application.ServeHTTP(response, request)

		assert.Equal(t, http.StatusConflict, response.Code)
	})
}
