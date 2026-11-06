// Package decisions defines the desired security state shared by storage and delivery.
package decisions

import "time"

// Decision describes the latest desired state for one address.
type Decision struct {
	// ID is stable across revisions for this address in this database.
	ID string `json:"id"`
	// Revision increases each time the desired state changes.
	Revision int64 `json:"revision"`
	// IP is the canonical address to block or release.
	IP string `json:"ipAddress"`
	// Active requests a block when true and a release when false.
	Active bool `json:"active"`
	// ExpiresAt is the deadline for the desired block.
	ExpiresAt time.Time `json:"expiresAt"`
	// Failures records the count that last triggered the decision.
	Failures int `json:"failures"`
}
