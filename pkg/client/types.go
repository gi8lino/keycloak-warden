package client

import (
	"fmt"
	"time"
)

// Decision is Warden's desired block or release state, independent of delivery.
type Decision struct {
	// ID remains stable across revisions of a decision.
	ID string `json:"id" yaml:"id"`
	// Revision increases when the effective desired state changes.
	Revision int64 `json:"revision" yaml:"revision"`
	// IP is the canonical address to block or release.
	IP string `json:"ipAddress" yaml:"ipAddress"`
	// State is either banned or unbanned.
	State string `json:"state" yaml:"state"`
	// ExpiresAt is the expiration of the desired ban.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
}

// Source describes an active automatic or manually requested reason for a ban.
type Source struct {
	// Kind is automatic or manual.
	Kind string `json:"kind" yaml:"kind"`
	// ExpiresAt is the expiration of this independent source.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
	// Reason is the optional operator explanation.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// Acknowledgement identifies a destination's last accepted decision revision.
type Acknowledgement struct {
	// Destination is the configured destination name.
	Destination string `json:"destination" yaml:"destination"`
	// Revision is the last successfully acknowledged revision.
	Revision int64 `json:"acknowledgedRevision" yaml:"acknowledgedRevision"`
}

// Record holds a decision with its active sources and delivery acknowledgements.
type Record struct {
	// Decision is Warden's desired state.
	Decision Decision `json:"decision" yaml:"decision"`
	// Sources are the currently active reasons to block the address.
	Sources []Source `json:"sources" yaml:"sources"`
	// Deliveries hold the last acknowledged revision per destination.
	Deliveries []Acknowledgement `json:"deliveries" yaml:"deliveries"`
}

// ManualBanRequest requests creation or extension of an operator-controlled ban.
type ManualBanRequest struct {
	// IP is the address the operator requests to block.
	IP string
	// Duration specifies the requested ban lifetime.
	Duration time.Duration
	// Reason records the operator explanation.
	Reason string
}

// TaskStatus describes the outcome of one scheduled or manual maintenance task.
type TaskStatus struct {
	// Running reports whether the task is currently executing.
	Running bool `json:"running" yaml:"running"`
	// LastAttemptAt is the most recent attempt start time.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
	// LastSuccessAt is the most recent successful finish time.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty" yaml:"lastSuccessAt,omitempty"`
	// LastError describes the last failed attempt, if any.
	LastError string `json:"lastError,omitempty" yaml:"lastError,omitempty"`
}

// Maintenance is the housekeeping status returned by the application API.
type Maintenance struct {
	// Prune reports observation cleanup.
	Prune TaskStatus `json:"prune" yaml:"prune"`
	// Optimize reports SQLite planner optimization.
	Optimize TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval describes the configured cleanup frequency.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval describes the configured optimization frequency.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
}

// Error identifies a non-2xx administrative API response.
type Error struct {
	// Code is the upstream HTTP status code.
	Code int
	// Message is an optional bounded server-supplied explanation.
	Message string
}

// Error describes an unsuccessful request without exposing the bearer token.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("application HTTP %d", e.Code)
	}
	return fmt.Sprintf("application HTTP %d: %s", e.Code, e.Message)
}
