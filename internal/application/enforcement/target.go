package enforcement

// Target combines an outbound provider with its resolved delivery attempt budget.
type Target struct {
	// Identity fingerprints the resolved destination without storing credentials.
	Identity string
	// Provider reconciles desired decisions with the external destination.
	Provider Provider
	// MaxAttempts includes the first delivery and any subsequent retries.
	MaxAttempts int
}
