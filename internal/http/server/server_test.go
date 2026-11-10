package server_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/metrics"
	"github.com/gi8lino/keycloak-warden/internal/signing"
)

// noopProcessor accepts events without generating decisions in HTTP tests.
type noopProcessor struct{}

// Process accepts test events without persistence.
func (noopProcessor) Process(context.Context, events.Envelope, time.Time) (*decisions.Decision, error) {
	return nil, nil
}

type readiness bool

// Ping returns the configured readiness state.
func (ready readiness) Ping(context.Context) error {
	if !ready {
		return assert.AnError
	}
	return nil
}

// TestAccessLogFields confirms that only application requests emit selected access-log fields.
func TestAccessLogFields(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handlers := newTestServer(server.Config{
		AccessLog: true,
		Logger:    logger,
		Secret:    "secret",
		Processor: noopProcessor{},
		Readiness: readiness(true),
	})

	// Missing content type is rejected before authentication; only the path is logged.
	rec := httptest.NewRecorder()
	handlers.Application.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/events?private=secret", nil))
	require.Equal(t, http.StatusUnsupportedMediaType, rec.Code)

	logged := logs.String()
	assert.Contains(t, logged, `"event":"request_complete"`)
	assert.Contains(t, logged, `"method":"POST"`)
	assert.Contains(t, logged, `"path":"/events"`)
	assert.Contains(t, logged, `"status":415`)
	assert.Contains(t, logged, `"duration":`)
	assert.NotContains(t, logged, "private=secret")
	assert.NotContains(t, logged, `"error_reference":`)

	// Health probes are served by a separate, unlogged management handler.
	before := logs.Len()
	health := httptest.NewRecorder()
	handlers.Management.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, health.Code)
	assert.Equal(t, before, logs.Len())

	// The access-log option remains opt-in for the application.
	logs.Reset()
	disabled := newTestServer(server.Config{
		Logger:    logger,
		Secret:    "secret",
		Processor: noopProcessor{},
		Readiness: readiness(true),
	})
	missing := httptest.NewRecorder()
	disabled.Application.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/not-found", nil))
	require.Equal(t, http.StatusNotFound, missing.Code)
	assert.Empty(t, logs.String())
}

func TestNew(t *testing.T) {
	t.Parallel()

	newHandlers := func(ready bool) (http.Handler, http.Handler) {
		h := newTestServer(server.Config{
			Secret:     "secret",
			Logger:     slog.Default(),
			Processor:  noopProcessor{},
			Readiness:  readiness(ready),
			WorkerDone: make(chan struct{}),
		})
		return h.Application, h.Management
	}
	t.Run("management liveness", func(t *testing.T) {
		t.Parallel()

		_, management := newHandlers(true)
		rec := httptest.NewRecorder()
		management.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("management readiness", func(t *testing.T) {
		t.Parallel()

		_, management := newHandlers(true)
		rec := httptest.NewRecorder()
		management.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("management reports stopped action worker", func(t *testing.T) {
		t.Parallel()

		done := make(chan struct{})
		handlers := newTestServer(server.Config{
			Logger:     slog.Default(),
			Readiness:  readiness(true),
			WorkerDone: done,
		})

		ready := httptest.NewRecorder()
		handlers.Management.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		require.Equal(t, http.StatusOK, ready.Code)

		close(done)
		ready = httptest.NewRecorder()
		handlers.Management.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusServiceUnavailable, ready.Code)
		assert.Contains(t, ready.Body.String(), "Action worker unavailable")

		live := httptest.NewRecorder()
		handlers.Management.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		assert.Equal(t, http.StatusOK, live.Code)
	})

	t.Run("management rejects missing action worker", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			Logger:    slog.Default(),
			Readiness: readiness(true),
		})
		ready := httptest.NewRecorder()
		handlers.Management.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusServiceUnavailable, ready.Code)
		assert.Contains(t, ready.Body.String(), "Action worker unavailable")
	})

	t.Run("management rejects ingestion", func(t *testing.T) {
		t.Parallel()

		_, management := newHandlers(true)
		rec := httptest.NewRecorder()
		management.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/events", nil))

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("application requires Snitch authentication", func(t *testing.T) {
		t.Parallel()

		application, _ := newHandlers(true)
		rec := httptest.NewRecorder()
		application.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/events", nil))

		assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
	})

	t.Run("application does not expose health", func(t *testing.T) {
		t.Parallel()

		application, _ := newHandlers(true)
		rec := httptest.NewRecorder()
		application.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("management reports unready SQLite", func(t *testing.T) {
		t.Parallel()

		_, management := newHandlers(false)
		rec := httptest.NewRecorder()
		management.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("middleware rejects unsigned JSON", func(t *testing.T) {
		t.Parallel()

		application, _ := newHandlers(true)
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(`{"invalid":true}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		application.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("middleware accepts signed envelope", func(t *testing.T) {
		t.Parallel()

		application, _ := newHandlers(true)
		payload := `{"schemaVersion":1,"id":"event","source":"keycloak","type":"LOGIN","timestamp":"2026-11-05T15:00:00Z"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Snitch-Timestamp", timestamp)
		req.Header.Set("X-Snitch-Signature", signing.Signature("secret", timestamp, []byte(payload)))
		rec := httptest.NewRecorder()
		application.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
	t.Run("disabled metrics expose no route", func(t *testing.T) {
		t.Parallel()

		registry := metrics.NewRegistry(false, "test")
		handlers := newTestServer(server.Config{
			Logger:         slog.Default(),
			Readiness:      readiness(true),
			MetricsEnabled: false,
			Metrics:        registry,
		})
		response := httptest.NewRecorder()
		handlers.Management.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

		assert.Equal(t, http.StatusNotFound, response.Code)
	})

	t.Run("metrics available only on unprefixed management listener", func(t *testing.T) {
		t.Parallel()

		registry := metrics.NewRegistry(true, "integration")
		handlers := newTestServer(server.Config{
			Logger:         slog.Default(),
			Readiness:      readiness(true),
			Processor:      noopProcessor{},
			Secret:         "keycloak-secret",
			AdminToken:     "admin-secret",
			Bans:           noOpBanService{},
			MetricsEnabled: true,
			Metrics:        registry,
			RoutePrefix:    "/warden",
		})

		appMetrics := httptest.NewRecorder()
		handlers.Application.ServeHTTP(appMetrics, httptest.NewRequest(http.MethodGet, "/warden/metrics", nil))
		assert.Equal(t, http.StatusNotFound, appMetrics.Code)

		managementPrefixed := httptest.NewRecorder()
		handlers.Management.ServeHTTP(managementPrefixed, httptest.NewRequest(http.MethodGet, "/warden/metrics", nil))
		assert.Equal(t, http.StatusNotFound, managementPrefixed.Code)

		unauthorized := httptest.NewRecorder()
		handlers.Application.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/warden/bans", nil))
		require.Equal(t, http.StatusUnauthorized, unauthorized.Code)

		authorized := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/warden/bans", nil)
		request.Header.Set("Authorization", "Bearer admin-secret")
		handlers.Application.ServeHTTP(authorized, request)
		require.Equal(t, http.StatusOK, authorized.Code)

		response := httptest.NewRecorder()
		handlers.Management.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		require.Equal(t, http.StatusOK, response.Code)

		body := response.Body.String()
		assert.Contains(t, body, `warden_build_info{version="integration"} 1`)
		assert.Contains(t, body, `warden_http_requests_total{code="200",method="GET",route="/bans"} 1`)
		assert.Contains(t, body, `warden_http_requests_total{code="401",method="GET",route="/bans"} 1`)
		assert.NotContains(t, body, "203.0.113")
	})

	t.Run("route prefix applies only to application", func(t *testing.T) {
		t.Parallel()

		handlers := newTestServer(server.Config{
			Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			Readiness:   readiness(true),
			Processor:   noopProcessor{},
			Secret:      "keycloak-secret",
			RoutePrefix: "/warden",
		})

		health := httptest.NewRecorder()
		handlers.Management.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		assert.Equal(t, http.StatusOK, health.Code)

		wrongHealth := httptest.NewRecorder()
		handlers.Management.ServeHTTP(wrongHealth, httptest.NewRequest(http.MethodGet, "/warden/healthz", nil))
		assert.Equal(t, http.StatusNotFound, wrongHealth.Code)

		outside := httptest.NewRecorder()
		handlers.Application.ServeHTTP(outside, httptest.NewRequest(http.MethodPost, "/events", strings.NewReader("{}")))
		assert.Equal(t, http.StatusNotFound, outside.Code)

		inside := httptest.NewRecorder()
		handlers.Application.ServeHTTP(inside, httptest.NewRequest(http.MethodPost, "/warden/events", strings.NewReader("{}")))
		assert.NotEqual(t, http.StatusNotFound, inside.Code)

		// Prefix mounting must preserve the Snitch authentication middleware.
		payload := `{"schemaVersion":1,"id":"prefixed-event","source":"keycloak","type":"LOGIN","timestamp":"2026-11-05T15:00:00Z"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		request := httptest.NewRequest(http.MethodPost, "/warden/events", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Snitch-Timestamp", timestamp)
		request.Header.Set("X-Snitch-Signature", signing.Signature("keycloak-secret", timestamp, []byte(payload)))
		authorized := httptest.NewRecorder()
		handlers.Application.ServeHTTP(authorized, request)
		assert.Equal(t, http.StatusNoContent, authorized.Code)

		redirect := httptest.NewRecorder()
		handlers.Application.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/warden", nil))
		assert.Equal(t, http.StatusPermanentRedirect, redirect.Code)
		assert.Equal(t, "/warden/", redirect.Header().Get("Location"))
	})
}
