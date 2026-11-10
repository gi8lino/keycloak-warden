// Package decisions defines the desired security state shared by storage and delivery.
package decisions

import "time"

// State identifies the desired blocking state, independently of delivery status.
type State string

const (
	// StateBanned requests that destinations block the address.
	StateBanned State = "banned"
	// StateUnbanned requests that destinations release the address.
	StateUnbanned State = "unbanned"
)

// Valid reports whether the state is a supported desired blocking state.
func (s State) Valid() bool {
	return s == StateBanned || s == StateUnbanned
}

// Decision describes the latest desired state for one address.
type Decision struct {
	// ID is stable across revisions for this address in this database.
	ID string `json:"id"`
	// Revision increases each time the desired state changes.
	Revision int64 `json:"revision"`
	// IP is the canonical address to block or release.
	IP string `json:"ipAddress"`
	// State is the desired block or release operation.
	State State `json:"state"`
	// ExpiresAt is the deadline for the desired block.
	ExpiresAt time.Time `json:"expiresAt"`
	// Failures records the count that last triggered the decision.
	Failures int `json:"failures"`
}
