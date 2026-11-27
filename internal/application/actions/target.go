package actions

// Target combines an outbound provider with its resolved delivery attempt budget.
type Target struct {
	// Provider reconciles desired decisions with the external destination.
	Provider Provider
	// MaxAttempts includes the first delivery and any subsequent retries.
	MaxAttempts int
}
