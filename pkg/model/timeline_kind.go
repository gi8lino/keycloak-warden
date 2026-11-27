package model

// TimelineKind identifies the persisted fact represented by a timeline entry.
type TimelineKind string

const (
	// TimelineSource records a change to an independent ban source.
	TimelineSource TimelineKind = "source"
	// TimelineDecision records a revised effective decision.
	TimelineDecision TimelineKind = "decision"
	// TimelineAttempt records a completed destination delivery.
	TimelineAttempt TimelineKind = "attempt"
	// TimelineRetry records an operator-requested delivery retry.
	TimelineRetry TimelineKind = "retry"
)

// Valid reports whether the kind identifies a supported timeline entry.
func (k TimelineKind) Valid() bool {
	switch k {
	case TimelineSource, TimelineDecision, TimelineAttempt, TimelineRetry:
		return true
	default:
		return false
	}
}
