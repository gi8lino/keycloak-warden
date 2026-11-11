package endpoint_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	httpkitmiddleware "github.com/containeroo/httpkit/middleware"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
	"github.com/gi8lino/keycloak-warden/internal/http/middleware"
	"github.com/gi8lino/keycloak-warden/internal/metrics"
	"github.com/gi8lino/keycloak-warden/internal/signing"
)

// capture receives authenticated envelopes and keeps their original source details.
type capture struct {
	// events collects normalized inputs received by the test processor.
	events []events.Envelope
	// decision is the simulated result of a detection threshold being reached.
	decision *decisions.Decision
	// result defines a non-changing detection outcome for event log tests.
	result ingestion.Result
	// err simulates invalid or unavailable event processing.
	err error
}

// Process records the event after HTTP authentication and application dispatch.
func (c *capture) Process(_ context.Context, e events.Envelope, _ time.Time) (ingestion.Result, error) {
	c.events = append(c.events, e)
	if c.err != nil {
		return ingestion.Result{}, c.err
	}
	if c.decision != nil {
		return ingestion.Result{Outcome: ingestion.OutcomeUpdated, Decision: c.decision}, nil
	}
	return c.result, nil
}

// post constructs a signed request and returns the endpoint status.
func post(h http.Handler, body, secret string, now time.Time) int {
	ts := strconv.FormatInt(now.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/events", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Snitch-Timestamp", ts)
	r.Header.Set("X-Snitch-Signature", signing.Signature(secret, ts, []byte(body)))
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestEvents(t *testing.T) {
	t.Parallel()

	const body = `{"id":"one","source":"keycloak","type":"LOGIN_ERROR","schemaVersion":1,"timestamp":"2026-11-05T15:00:00Z","ipAddress":null}`
	newHandler := func(c *capture) http.Handler {
		return httpkitmiddleware.Chain(endpoint.Events(c, slog.Default(), metrics.NewRegistry(false, "test")), middleware.AuthenticateSnitch("key"))
	}

	t.Run("passes a signed native envelope without trusting forwarded IP headers", func(t *testing.T) {
		t.Parallel()

		c := new(capture)

		require.Equal(t, http.StatusNoContent, post(newHandler(c), body, "key", time.Now()))
		require.Len(t, c.events, 1)
		assert.Empty(t, c.events[0].IP)
	})

	t.Run("rejects wrong signature before the endpoint", func(t *testing.T) {
		t.Parallel()

		c := new(capture)

		assert.Equal(t, http.StatusUnauthorized, post(newHandler(c), body, "wrong", time.Now()))
		assert.Empty(t, c.events)
	})

	t.Run("rejects old timestamp", func(t *testing.T) {
		t.Parallel()

		c := new(capture)

		assert.Equal(t, http.StatusUnauthorized, post(newHandler(c), body, "key", time.Now().Add(-6*time.Minute)))
		assert.Empty(t, c.events)
	})

	t.Run("rejects oversized body", func(t *testing.T) {
		t.Parallel()

		c := new(capture)
		assert.Equal(
			t,
			http.StatusRequestEntityTooLarge,
			post(newHandler(c), strings.Repeat("x", 65537), "key", time.Now()),
		)

		assert.Empty(t, c.events)
	})

	t.Run("rejects malformed JSON after authenticating", func(t *testing.T) {
		t.Parallel()

		c := new(capture)

		assert.Equal(t, http.StatusBadRequest, post(newHandler(c), "{bad", "key", time.Now()))
		assert.Empty(t, c.events)
	})

	t.Run("rejects multiple JSON values", func(t *testing.T) {
		t.Parallel()

		c := new(capture)

		assert.Equal(t, http.StatusBadRequest, post(newHandler(c), body+` {}`, "key", time.Now()))
		assert.Empty(t, c.events)
	})
}

// TestEventsRealmTelemetry verifies realm-scoped metrics and logs for committed decisions.
func TestEventsRealmTelemetry(t *testing.T) {
	t.Parallel()

	const body = `{"id":"one","source":"keycloak","type":"LOGIN_ERROR","schemaVersion":1,"timestamp":"2026-11-05T15:00:00Z","realmId":"hq","ipAddress":"203.0.113.5"}`

	t.Run("records processed event with its source realm", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		registry := metrics.NewRegistry(true, "test")
		processor := &capture{result: ingestion.Result{
			Outcome: ingestion.OutcomeBelowThreshold, IP: "203.0.113.5", Failures: 1, Threshold: 5,
		}}
		handler := httpkitmiddleware.Chain(endpoint.Events(processor, logger, registry), middleware.AuthenticateSnitch("key"))

		require.Equal(t, http.StatusNoContent, post(handler, body, "key", time.Now()))
		require.Len(t, processor.events, 1)
		assert.Equal(t, "hq", processor.events[0].RealmID)
		assert.Contains(t, logs.String(), `"event":"detection_threshold_not_reached"`)
		assert.Contains(t, logs.String(), `"failures":1`)
		assert.Contains(t, logs.String(), `"threshold":5`)

		output := httptest.NewRecorder()
		registry.Metrics().ServeHTTP(output, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		assert.Contains(t, output.Body.String(), `warden_snitch_events_total{event_type="LOGIN_ERROR",realm="hq"} 1`)
		assert.NotContains(t, output.Body.String(), "warden_automatic_ban_decisions_total{trigger_realm=")
	})

	t.Run("attributes ban decision to triggering realm", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		registry := metrics.NewRegistry(true, "test")
		processor := &capture{decision: &decisions.Decision{
			ID:       "decision",
			IP:       "203.0.113.5",
			Revision: 14,
			State:    decisions.StateBanned,
		}}
		handler := httpkitmiddleware.Chain(endpoint.Events(processor, logger, registry), middleware.AuthenticateSnitch("key"))

		require.Equal(t, http.StatusNoContent, post(handler, body, "key", time.Now()))
		assert.Contains(t, logs.String(), `"trigger_realm_id":"hq"`)
		assert.Contains(t, logs.String(), `"trigger_event_id":"one"`)
		assert.Contains(t, logs.String(), `"revision":14`)
		assert.Contains(t, logs.String(), `"event":"automatic_ban_updated"`)
		assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("\n")), "a decision change should emit one log entry")
		assert.NotContains(t, logs.String(), `"event":"automatic_ban_created"`)
		assert.NotContains(t, logs.String(), `"event":"security_event_processed"`)

		output := httptest.NewRecorder()
		registry.Metrics().ServeHTTP(output, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		assert.Contains(t, output.Body.String(), `warden_automatic_ban_decisions_total{trigger_realm="hq"} 1`)
	})

	t.Run("rejects unauthenticated requests without emitting realm metrics", func(t *testing.T) {
		t.Parallel()

		registry := metrics.NewRegistry(true, "test")
		processor := new(capture)
		handler := httpkitmiddleware.Chain(endpoint.Events(processor, slog.Default(), registry), middleware.AuthenticateSnitch("key"))

		assert.Equal(t, http.StatusUnauthorized, post(handler, body, "wrong", time.Now()))
		assert.Empty(t, processor.events)
		output := httptest.NewRecorder()
		registry.Metrics().ServeHTTP(output, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		assert.NotContains(t, output.Body.String(), "warden_snitch_events_total{")
	})
}

// TestEventDiagnosticLogging verifies that diagnostic outcomes are DEBUG-only and contract errors are WARN.
func TestEventDiagnosticLogging(t *testing.T) {
	t.Parallel()

	const body = `{"id":"one","source":"keycloak","type":"LOGIN_ERROR","schemaVersion":1,"timestamp":"2026-11-05T15:00:00Z","realmId":"hq","ipAddress":"203.0.113.5"}`
	tests := []struct {
		name   string
		result ingestion.Result
		event  string
	}{
		{name: "ignored event", result: ingestion.Result{Outcome: ingestion.OutcomeIgnored, Reason: "unsupported_event_type"}, event: "security_event_ignored"},
		{name: "duplicate", result: ingestion.Result{Outcome: ingestion.OutcomeDuplicate, IP: "203.0.113.5"}, event: "security_event_duplicate"},
		{name: "below threshold", result: ingestion.Result{Outcome: ingestion.OutcomeBelowThreshold, IP: "203.0.113.5", Failures: 2, Threshold: 5}, event: "detection_threshold_not_reached"},
		{name: "unchanged decision", result: ingestion.Result{Outcome: ingestion.OutcomeUnchanged, IP: "203.0.113.5", Failures: 5, Threshold: 5}, event: "decision_unchanged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
				var logs bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: level}))
				processor := &capture{result: tt.result}
				handler := httpkitmiddleware.Chain(endpoint.Events(processor, logger, metrics.NewRegistry(false, "test")), middleware.AuthenticateSnitch("key"))
				require.Equal(t, http.StatusNoContent, post(handler, body, "key", time.Now()))
				if level == slog.LevelDebug {
					assert.Contains(t, logs.String(), `"event":"`+tt.event+`"`)
					assert.Contains(t, logs.String(), `"level":"DEBUG"`)
				} else {
					assert.Empty(t, logs.String(), "routine non-changing events should be silent without --debug")
				}
			}
		})
	}

	t.Run("malformed authenticated JSON logs a warning without the body", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		handler := httpkitmiddleware.Chain(endpoint.Events(new(capture), logger, metrics.NewRegistry(false, "test")), middleware.AuthenticateSnitch("key"))
		require.Equal(t, http.StatusBadRequest, post(handler, `{bad`, "key", time.Now()))
		assert.Contains(t, logs.String(), `"level":"WARN"`)
		assert.Contains(t, logs.String(), `"reason":"invalid_json"`)
		assert.NotContains(t, logs.String(), `{bad`)
	})

	t.Run("invalid authenticated event logs a warning", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		processor := &capture{err: ingestion.ErrInvalidEvent}
		handler := httpkitmiddleware.Chain(endpoint.Events(processor, logger, metrics.NewRegistry(false, "test")), middleware.AuthenticateSnitch("key"))
		require.Equal(t, http.StatusBadRequest, post(handler, body, "key", time.Now()))
		assert.Contains(t, logs.String(), `"level":"WARN"`)
		assert.Contains(t, logs.String(), `"event":"security_event_rejected"`)
	})

	t.Run("invalid signature does not generate event warning", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		handler := httpkitmiddleware.Chain(endpoint.Events(new(capture), logger, metrics.NewRegistry(false, "test")), middleware.AuthenticateSnitch("key"))
		require.Equal(t, http.StatusUnauthorized, post(handler, body, "wrong", time.Now()))
		assert.Empty(t, logs.String())
	})
}
