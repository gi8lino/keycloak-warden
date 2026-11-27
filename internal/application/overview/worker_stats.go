package overview

import "time"

// QueueStats summarizes persisted delivery work and the most recent completed attempt.
type QueueStats struct {
	// PendingDeliveries counts current revisions not yet attempted.
	PendingDeliveries int `json:"pendingDeliveries" yaml:"pendingDeliveries"`
	// RetryingDeliveries counts current revisions waiting for another attempt.
	RetryingDeliveries int `json:"retryingDeliveries" yaml:"retryingDeliveries"`
	// ExhaustedDeliveries counts current revisions whose attempt budgets were consumed.
	ExhaustedDeliveries int `json:"exhaustedDeliveries" yaml:"exhaustedDeliveries"`
	// ActiveBans counts addresses with at least one unexpired ban source.
	ActiveBans int `json:"activeBans" yaml:"activeBans"`
	// LastAttemptAt is the latest completed attempt across all revisions and runs.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
}
