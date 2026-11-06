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

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// EventProcessor processes a source event after the HTTP middleware authenticates it.
type EventProcessor interface {
	Process(ctx context.Context, envelope events.Envelope, now time.Time) (*decisions.Decision, error)
}

// Events accepts the verified Snitch v1 JSON envelope at POST /events.
// All authentication is performed by middleware, not by this endpoint.
func Events(processor EventProcessor, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var envelope events.Envelope
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&envelope); err != nil {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid JSON event.")
			return
		}

		// The bounded middleware body must contain exactly one JSON value.
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			httpresponse.Problem(w, http.StatusBadRequest, "Expected one JSON event.")
			return
		}

		_, err := processor.Process(r.Context(), envelope, time.Now())
		if errors.Is(err, ingestion.ErrInvalidEvent) {
			httpresponse.Problem(w, http.StatusBadRequest, "Invalid security event.")
			return
		}

		if err != nil {
			logger.Error("processing security event failed", "error", err)
			httpresponse.Problem(w, http.StatusServiceUnavailable, "Event processing unavailable.")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
