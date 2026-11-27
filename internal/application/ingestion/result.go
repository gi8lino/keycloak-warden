package ingestion

import (
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// Outcome identifies why a valid security event did or did not revise a decision.
type Outcome string

const (
	// OutcomeIgnored indicates the event did not match the configured detection rule.
	OutcomeIgnored Outcome = "ignored"
	// OutcomeDuplicate indicates the event was previously observed.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeBelowThreshold indicates a matching event has not reached a rule threshold.
	OutcomeBelowThreshold Outcome = "below_threshold"
	// OutcomeUnchanged indicates the threshold was met without revising the desired decision.
	OutcomeUnchanged Outcome = "unchanged"
	// OutcomeProtected indicates a matching event was excluded before recording a failure.
	OutcomeProtected Outcome = "protected"
	// OutcomeObserved indicates a hypothetical ban qualified without enforcement.
	OutcomeObserved Outcome = "observed"
	// OutcomeThresholdMet indicates a rule remained above threshold without a new incident.
	OutcomeThresholdMet Outcome = "threshold_met"
	// OutcomeIncident indicates a threshold hit with no ban action.
	OutcomeIncident Outcome = "incident"
	// OutcomeUpdated indicates the effective desired decision was revised.
	OutcomeUpdated Outcome = "updated"
)

// Result describes the committed outcome of processing one authenticated security event.
type Result struct {
	// Outcome explains the event's effect on detection and desired state.
	Outcome Outcome
	// Decision is set only when processing revised the effective desired state.
	Decision *model.Decision
	// IP is the canonical address when the producer supplied a valid address.
	IP string
	// Reason explains why an otherwise valid event did not match the rule.
	Reason string
	// Evaluations contains counts for every evaluated rule.
	Evaluations []detection.Evaluation
	// Incidents contains committed named rule threshold hits.
	Incidents []model.Incident
}
