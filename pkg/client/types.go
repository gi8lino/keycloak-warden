package client

import (
	"fmt"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// Decision is Warden's desired block or release state, independent of delivery.
type Decision struct {
	// ID remains stable across revisions of a decision.
	ID string `json:"id" yaml:"id"`
	// Revision increases when the effective desired state changes.
	Revision int64 `json:"revision" yaml:"revision"`
	// IP is the canonical address to block or release.
	IP string `json:"ipAddress" yaml:"ipAddress"`
	// State is the desired blocking state.
	State decisionstate.State `json:"state" yaml:"state"`
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

// SourceChange is an immutable source mutation, separate from the decision revision journal.
type SourceChange struct {
	// ID is the monotonically increasing source journal entry.
	ID int64 `json:"id" yaml:"id"`
	// Kind is the source affected by the change.
	Kind string `json:"kind" yaml:"kind"`
	// Action is added, updated, or removed.
	Action string `json:"action" yaml:"action"`
	// ExpiresAt records the source expiry at the time of the change.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
	// Reason records the source explanation at the time of the change.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	// ChangedAt records when Warden persisted the mutation.
	ChangedAt time.Time `json:"changedAt" yaml:"changedAt"`
}

// Record holds a decision with its active sources and delivery acknowledgements.
type Record struct {
	// Decision is Warden's desired state.
	Decision Decision `json:"decision" yaml:"decision"`
	// Sources are the currently active reasons to block the address.
	Sources []Source `json:"sources" yaml:"sources"`
	// SourceChanges contains the latest source additions, edits, and removals on individual reads.
	SourceChanges []SourceChange `json:"sourceChanges,omitempty" yaml:"sourceChanges,omitempty"`
	// CurrentDeliveries reports every current-revision destination regardless of history pagination.
	CurrentDeliveries []Delivery `json:"currentDeliveries,omitempty" yaml:"currentDeliveries,omitempty"`
	// DeliveryHistory contains per-revision history on individual decision reads.
	DeliveryHistory []Delivery `json:"deliveryHistory,omitempty" yaml:"deliveryHistory,omitempty"`
	// HistoryPage identifies the one-based page included in an individual inspection.
	HistoryPage int `json:"historyPage,omitempty" yaml:"historyPage,omitempty"`
	// HistoryNextPage identifies the next older page; zero means the last page.
	HistoryNextPage int `json:"historyNextPage,omitempty" yaml:"historyNextPage,omitempty"`
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
