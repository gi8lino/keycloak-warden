// Package endpoint adapts HTTP requests and responses to application use cases.
package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// EventProcessor processes a source event after the HTTP middleware authenticates it.
type EventProcessor interface {
	Process(ctx context.Context, envelope events.Envelope, now time.Time) (ingestion.Result, error)
}

// Events processes authenticated Snitch v1 envelopes and returns an ingestion result.
func Events(processor EventProcessor, logger *slog.Logger, metrics EventMetrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var envelope events.Envelope
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&envelope); err != nil {
			logger.Warn(
				"security event rejected",
				"event", "security_event_rejected",
				"reason", "invalid_json",
			)
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid JSON event.")
			return
		}

		// The bounded middleware body must contain exactly one JSON value.
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			logger.Warn(
				"security event rejected",
				"event", "security_event_rejected",
				"reason", "multiple_or_invalid_json_values",
			)
			httpresponse.Problem(w, http.StatusBadRequest, "Expected one JSON event.")
			return
		}

		result, err := processor.Process(r.Context(), envelope, time.Now())
		if errors.Is(err, ingestion.ErrInvalidEvent) {
			logger.Warn(
				"security event rejected",
				"event", "security_event_rejected",
				"event_id", envelope.ID,
				"event_type", envelope.Kind,
				"realm_id", envelope.RealmID,
				"reason", "invalid_event",
			)
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid security event.")
			return
		}

		if err != nil {
			logger.Warn(
				"processing security event failed",
				"event", "security_event_processing_failed",
				"realm_id", envelope.RealmID,
				"error", err,
			)
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Event processing unavailable.")
			return
		}

		metrics.RecordProcessedEvent(
			envelope.RealmID,
			envelope.Kind,
			result.Decision != nil,
		)

		logEventOutcome(logger, envelope, result)

		w.WriteHeader(http.StatusNoContent)
	}
}
