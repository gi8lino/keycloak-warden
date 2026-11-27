package model

// DecisionState identifies the desired blocking state independently of delivery status.
type DecisionState string

const (
	// DecisionBanned requests that destinations block the address.
	DecisionBanned DecisionState = "banned"
	// DecisionUnbanned requests that destinations release the address.
	DecisionUnbanned DecisionState = "unbanned"
)

// Valid reports whether the state represents a supported desired blocking state.
func (s DecisionState) Valid() bool { return s == DecisionBanned || s == DecisionUnbanned }
