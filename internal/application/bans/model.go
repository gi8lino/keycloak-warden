package bans

import (
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

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
	Kind SourceKind `json:"kind"`
	// ExpiresAt is the UTC deadline for this source.
	ExpiresAt time.Time `json:"expiresAt"`
	// Reason records the operator explanation for the requested block.
	Reason string `json:"reason,omitempty"`
}

// Record describes a persisted decision, its active sources, and delivery acknowledgements.
type Record struct {
	// Decision contains the effective desired state for the address.
	Decision decisions.Decision `json:"decision"`
	// Sources contains the independent active reasons for the block.
	Sources []Source `json:"sources"`
	// Deliveries records each destination’s acknowledged revision.
	Deliveries []decisions.Acknowledgement `json:"deliveries"`
}

// ManualBanRequest specifies a new or extended operator-requested block.
type ManualBanRequest struct {
	// IP is the reported client address, provided by the operator.
	IP string
	// Duration specifies how long the requested manual block should last.
	Duration time.Duration
	// Reason records the operator explanation for the requested block.
	Reason string
}
