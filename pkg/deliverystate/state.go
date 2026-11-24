// Package deliverystate defines delivery progress and attempt outcomes shared by the application and client.
package deliverystate

// Status identifies the lifecycle of a destination's delivery of a decision revision.
type Status string

const (
	// StatusPending means a revision is queued but has not yet been attempted.
	StatusPending Status = "pending"
	// StatusRetrying means a failed delivery is scheduled for another attempt.
	StatusRetrying Status = "retrying"
	// StatusDelivered means the destination acknowledged a revision.
	StatusDelivered Status = "delivered"
	// StatusExhausted means the revision has reached its configured attempt limit.
	StatusExhausted Status = "exhausted"
	// StatusSuperseded means a newer revision replaced unfinished work.
	StatusSuperseded Status = "superseded"
)

// Valid reports whether s represents a known delivery status.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusRetrying, StatusDelivered, StatusExhausted, StatusSuperseded:
		return true
	default:
		return false
	}
}

// Outcome identifies the result of one completed outbound attempt.
type Outcome string

const (
	// OutcomeSucceeded means the receiver accepted the request.
	OutcomeSucceeded Outcome = "succeeded"
	// OutcomeFailed means the receiver rejected the request or the call failed.
	OutcomeFailed Outcome = "failed"
)

// Valid reports whether o represents a known attempt outcome.
func (o Outcome) Valid() bool { return o == OutcomeSucceeded || o == OutcomeFailed }

// Current reports whether the status can describe a decision's latest revision.
// Superseded belongs exclusively to older revisions in the historical timeline.
func (s Status) Current() bool {
	switch s {
	case StatusPending, StatusRetrying, StatusDelivered, StatusExhausted:
		return true
	default:
		return false
	}
}
