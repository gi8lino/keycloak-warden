package model

// DeliveryStatus identifies the lifecycle of a destination's delivery of a decision revision.
type DeliveryStatus string

const (
	// DeliveryPending means a revision is queued but has not yet been attempted.
	DeliveryPending DeliveryStatus = "pending"
	// DeliveryRetrying means a failed delivery is scheduled for another attempt.
	DeliveryRetrying DeliveryStatus = "retrying"
	// DeliveryDelivered means the destination acknowledged a revision.
	DeliveryDelivered DeliveryStatus = "delivered"
	// DeliveryExhausted means the revision has reached its configured attempt limit.
	DeliveryExhausted DeliveryStatus = "exhausted"
	// DeliverySuperseded means a newer revision replaced unfinished work.
	DeliverySuperseded DeliveryStatus = "superseded"
)

// Valid reports whether s represents a known delivery status.
func (s DeliveryStatus) Valid() bool {
	switch s {
	case DeliveryPending, DeliveryRetrying, DeliveryDelivered, DeliveryExhausted, DeliverySuperseded:
		return true
	default:
		return false
	}
}

// AttemptOutcome identifies the result of one completed outbound attempt.
type AttemptOutcome string

const (
	// AttemptSucceeded means the receiver accepted the request.
	AttemptSucceeded AttemptOutcome = "succeeded"
	// AttemptFailed means the receiver rejected the request or the call failed.
	AttemptFailed AttemptOutcome = "failed"
)

// Valid reports whether o represents a known attempt outcome.
func (o AttemptOutcome) Valid() bool { return o == AttemptSucceeded || o == AttemptFailed }

// Current reports whether the status can describe a decision's latest revision.
// Superseded belongs exclusively to older revisions in the historical timeline.
func (s DeliveryStatus) Current() bool {
	switch s {
	case DeliveryPending, DeliveryRetrying, DeliveryDelivered, DeliveryExhausted:
		return true
	default:
		return false
	}
}
