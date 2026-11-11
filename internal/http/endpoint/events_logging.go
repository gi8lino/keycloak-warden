package endpoint

import (
	"log/slog"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// logEventOutcome records the result of processing an authenticated security event.
func logEventOutcome(
	logger *slog.Logger,
	envelope events.Envelope,
	result ingestion.Result,
) {
	switch result.Outcome {
	case ingestion.OutcomeIgnored:
		logger.Debug(
			"security event ignored",
			"event", "security_event_ignored",
			"event_id", envelope.ID,
			"event_type", envelope.Kind,
			"realm_id", envelope.RealmID,
			"reason", result.Reason,
		)

	case ingestion.OutcomeDuplicate:
		logger.Debug(
			"duplicate security event ignored",
			"event", "security_event_duplicate",
			"event_id", envelope.ID,
			"realm_id", envelope.RealmID,
			"ip", result.IP,
		)

	case ingestion.OutcomeBelowThreshold:
		logger.Debug(
			"detection threshold not reached",
			"event", "detection_threshold_not_reached",
			"event_id", envelope.ID,
			"ip", result.IP,
			"failures", result.Failures,
			"threshold", result.Threshold,
		)

	case ingestion.OutcomeUnchanged:
		logger.Debug(
			"effective ban decision unchanged",
			"event", "decision_unchanged",
			"event_id", envelope.ID,
			"ip", result.IP,
			"failures", result.Failures,
			"threshold", result.Threshold,
		)

	case ingestion.OutcomeUpdated:
		if decision := result.Decision; decision != nil {
			logger.Info(
				"automatic ban updated",
				"event", "automatic_ban_updated",
				"decision_id", decision.ID,
				"revision", decision.Revision,
				"trigger_event_id", envelope.ID,
				"trigger_realm_id", envelope.RealmID,
				"ip", decision.IP,
				"expires_at", decision.ExpiresAt,
			)
		}
	}
}
