package model

import "time"

// RuntimeStatus describes the action worker's in-process lifecycle.
type RuntimeStatus struct {
	// State is idle, processing, or stopped.
	State WorkerState `json:"state" yaml:"state"`
	// StartedAt records when the worker goroutine was launched.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
}

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

// ActionWorker is the action worker's runtime state and durable queue summary.
type ActionWorker struct {
	// RuntimeStatus supplies the in-process lifecycle state.
	RuntimeStatus `yaml:",inline"`
	// QueueStats supplies the persisted delivery and ban statistics.
	QueueStats `yaml:",inline"`
	// NextDeadline is the earliest pending delivery or source expiry.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
}

// Workers is the combined observable worker state for administrators.
type Workers struct {
	// Actions handles expiry, ban deliveries, and retries.
	Actions ActionWorker `json:"actions" yaml:"actions"`
	// Maintenance handles periodic observation cleanup and SQLite optimization.
	Maintenance Maintenance `json:"maintenance" yaml:"maintenance"`
}

// TaskStatus describes the latest attempt for one maintenance operation.
type TaskStatus struct {
	// Running indicates that an attempt is currently in progress.
	Running bool `json:"running" yaml:"running"`
	// LastAttemptAt records when the most recent attempt began.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
	// LastSuccessAt records when the most recent successful attempt completed.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty" yaml:"lastSuccessAt,omitempty"`
	// LastError reports the last failed attempt, cleared after success.
	LastError string `json:"lastError,omitempty" yaml:"lastError,omitempty"`
}

// Maintenance is a safe snapshot of the maintenance worker and its scheduled tasks.
type Maintenance struct {
	// State is idle, processing, or stopped.
	State WorkerState `json:"state" yaml:"state"`
	// StartedAt records when the maintenance worker was started.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
	// Prune reports the last observation cleanup attempt.
	Prune TaskStatus `json:"prune" yaml:"prune"`
	// Optimize reports the last SQLite optimization attempt.
	Optimize TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval describes the configured recurring cleanup interval.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval describes the configured recurring optimization interval.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
}
