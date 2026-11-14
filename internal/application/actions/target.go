package actions

// Target combines an outbound provider with its resolved delivery attempt budget.
// The configuration is immutable after startup and is never persisted in SQLite.
type Target struct {
	// Provider reconciles desired decisions with the external destination.
	Provider Provider
	// MaxAttempts includes the first delivery and any subsequent retries.
	MaxAttempts int
}
