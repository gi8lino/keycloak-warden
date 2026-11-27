package model

import "time"

// Decision describes the latest desired state for one address.
type Decision struct {
	// ID is stable across revisions for this address in this database.
	ID string `json:"id" yaml:"id"`
	// Revision increases each time the desired state changes.
	Revision int64 `json:"revision" yaml:"revision"`
	// IP is the canonical address to block or release.
	IP string `json:"ipAddress" yaml:"ipAddress"`
	// State is the desired block or release operation.
	State DecisionState `json:"state" yaml:"state"`
	// ExpiresAt is the deadline for the desired block.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
}
