// Package decisionstate defines the desired blocking states shared by Warden and its public client.
package decisionstate

// State identifies the desired blocking state independently of delivery status.
type State string

const (
	// StateBanned requests that destinations block the address.
	StateBanned State = "banned"
	// StateUnbanned requests that destinations release the address.
	StateUnbanned State = "unbanned"
)

// Valid reports whether the state represents a supported desired blocking state.
func (s State) Valid() bool {
	return s == StateBanned || s == StateUnbanned
}
