package model

import "time"

// SourceKind distinguishes independent reasons for an effective block.
type SourceKind string

const (
	// SourceAutomatic represents the failed-login detection rule.
	SourceAutomatic SourceKind = "automatic"
	// SourceManual represents an operator-requested ban.
	SourceManual SourceKind = "manual"
)

// Source describes one active reason to block an IP address.
type Source struct {
	// Kind identifies the automatic or manual source of a block.
	Kind SourceKind `json:"kind" yaml:"kind"`
	// ExpiresAt is the UTC deadline for this source.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
	// Reason records the operator explanation for the requested block.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// SourceChange is a persisted source mutation, independent of effective decision revisions.
type SourceChange struct {
	// ID is the append-only sequence within Warden's source journal.
	ID int64 `json:"id" yaml:"id"`
	// Kind identifies the source that was added, edited, or removed.
	Kind SourceKind `json:"kind" yaml:"kind"`
	// Action describes the persisted mutation.
	Action string `json:"action" yaml:"action"`
	// ExpiresAt is the source expiry at the time of this mutation.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
	// Reason is the source explanation as it existed for the mutation.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	// ChangedAt is the timestamp at which SQLite recorded the change.
	ChangedAt time.Time `json:"changedAt" yaml:"changedAt"`
}

// Record describes a persisted decision, its active sources, and delivery acknowledgements.
type Record struct {
	// Decision contains the effective desired state for the address.
	Decision Decision `json:"decision" yaml:"decision"`
	// Sources contains the independent active reasons for the block.
	Sources []Source `json:"sources" yaml:"sources"`
	// SourceChanges contains the most recent persisted source edits for individual reads.
	SourceChanges []SourceChange `json:"sourceChanges,omitempty" yaml:"sourceChanges,omitempty"`
	// CurrentDeliveries reports every current-revision destination regardless of history pagination.
	CurrentDeliveries []Delivery `json:"currentDeliveries,omitempty" yaml:"currentDeliveries,omitempty"`
	// DeliveryHistory contains per-revision history on individual decision reads.
	DeliveryHistory []Delivery `json:"deliveryHistory,omitempty" yaml:"deliveryHistory,omitempty"`
	// HistoryPage identifies the one-based page included in an individual inspection.
	HistoryPage int `json:"historyPage,omitempty" yaml:"historyPage,omitempty"`
	// HistoryNextPage identifies the next older page; zero means the last page.
	HistoryNextPage int `json:"historyNextPage,omitempty" yaml:"historyNextPage,omitempty"`
	// Deliveries records each destination’s acknowledged revision.
	Deliveries []Acknowledgement `json:"deliveries" yaml:"deliveries"`
}
