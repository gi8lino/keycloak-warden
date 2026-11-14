package actions

import "time"

const (
	// FirstRetryDelay is the initial pause after a failed delivery.
	FirstRetryDelay = 10 * time.Second
	// MaxRetryDelay caps destination-wide exponential backoff.
	MaxRetryDelay = 5 * time.Minute
)

// NextRetryDelay doubles the previous destination pause up to the fixed cap.
// The policy is evaluated in the application; persistence stores its outcome.
func NextRetryDelay(previous time.Duration) time.Duration {
	if previous < FirstRetryDelay {
		return FirstRetryDelay
	}
	if previous >= MaxRetryDelay/2 {
		return MaxRetryDelay
	}
	return previous * 2
}
