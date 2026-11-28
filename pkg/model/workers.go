package model

import "time"

// RuntimeStatus describes the enforcement worker's in-process lifecycle.
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

// EnforcementWorker is the enforcement worker's runtime state and durable queue summary.
type EnforcementWorker struct {
	// RuntimeStatus supplies the in-process lifecycle state.
	RuntimeStatus `yaml:",inline"`
	// QueueStats supplies the persisted delivery and ban statistics.
	QueueStats `yaml:",inline"`
	// NextDeadline is the earliest pending delivery or source expiry.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
}

// NotificationWorker reports incident delivery state independently of enforcement.
type NotificationWorker struct {
	// Runtime is absent when no notification worker is configured.
	Runtime *RuntimeStatus `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	// PendingDeliveries counts occurrences not yet attempted in their current retry cycle.
	PendingDeliveries int `json:"pendingDeliveries" yaml:"pendingDeliveries"`
	// RetryingDeliveries counts occurrences waiting for another attempt.
	RetryingDeliveries int `json:"retryingDeliveries" yaml:"retryingDeliveries"`
	// ExhaustedDeliveries counts retained terminal failures.
	ExhaustedDeliveries int `json:"exhaustedDeliveries" yaml:"exhaustedDeliveries"`
	// Delivered counts retained acknowledged occurrences.
	Delivered int `json:"delivered" yaml:"delivered"`
	// NextDeadline is the earliest eligible destination queue head.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
	// LastAttemptAt is the latest recorded send completion.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
}

// Workers is the combined observable worker state for administrators.
type Workers struct {
	// Enforcement handles expiry, ban deliveries, and retries.
	Enforcement EnforcementWorker `json:"enforcement" yaml:"enforcement"`
	// Notifications reports independent incident delivery activity.
	Notifications NotificationWorker `json:"notifications" yaml:"notifications"`
	// Maintenance handles periodic database pruning and SQLite optimization.
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
	// Prune reports the last database pruning attempt.
	Prune TaskStatus `json:"prune" yaml:"prune"`
	// Optimize reports the last SQLite optimization attempt.
	Optimize TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval describes the configured recurring cleanup interval.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval describes the configured recurring optimization interval.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
	// ObservationRetention describes the effective lifetime of detection counting data.
	ObservationRetention string `json:"observationRetention" yaml:"observationRetention"`
	// IncidentRetention describes the configured lifetime of incident history and terminal notifications.
	IncidentRetention string `json:"incidentRetention" yaml:"incidentRetention"`
}
