package ingestion

import "github.com/gi8lino/keycloak-warden/internal/application/decisions"

// Outcome identifies why a valid security event did or did not revise a decision.
type Outcome string

const (
	// OutcomeIgnored indicates the event did not match the configured detection rule.
	OutcomeIgnored Outcome = "ignored"
	// OutcomeDuplicate indicates the event was previously observed.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeBelowThreshold indicates a new failure has not yet met the rule threshold.
	OutcomeBelowThreshold Outcome = "below_threshold"
	// OutcomeUnchanged indicates the threshold was met without revising the desired decision.
	OutcomeUnchanged Outcome = "unchanged"
	// OutcomeUpdated indicates the effective desired decision was revised.
	OutcomeUpdated Outcome = "updated"
)

// Result describes the committed outcome of processing one authenticated security event.
type Result struct {
	// Outcome explains the event's effect on detection and desired state.
	Outcome Outcome
	// Decision is set only when processing revised the effective desired state.
	Decision *decisions.Decision
	// IP is the canonical address when the producer supplied a valid address.
	IP string
	// Reason explains why an otherwise valid event did not match the rule.
	Reason string
	// Failures counts distinct observations in the current detection window.
	Failures int
	// Threshold is the configured minimum number of failures to trigger a ban.
	Threshold int
}
