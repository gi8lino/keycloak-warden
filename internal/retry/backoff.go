package retry

import (
	"errors"
	"time"
)

const (
	// DefaultMaxAttempts counts the initial delivery and subsequent retries.
	DefaultMaxAttempts = 3
	// DefaultInitialRetryDelay is the initial pause after a failed delivery.
	DefaultInitialRetryDelay = 10 * time.Second
	// DefaultMaxRetryDelay caps destination-wide exponential backoff.
	DefaultMaxRetryDelay = 5 * time.Minute
)

// RetryPolicy configures destination-wide exponential backoff.
type RetryPolicy struct {
	// InitialDelay is the initial pause after a failed delivery.
	InitialDelay time.Duration
	// MaxDelay caps exponential backoff.
	MaxDelay time.Duration
}

// DefaultRetryPolicy returns the default destination backoff settings.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		InitialDelay: DefaultInitialRetryDelay,
		MaxDelay:     DefaultMaxRetryDelay,
	}
}

// Validate checks the retry delays and their millisecond precision.
func (p RetryPolicy) Validate() error {
	if p.InitialDelay < time.Millisecond || p.InitialDelay%time.Millisecond != 0 {
		return errors.New("retry-initial-delay must be a positive whole number of milliseconds")
	}

	if p.MaxDelay < time.Millisecond || p.MaxDelay%time.Millisecond != 0 {
		return errors.New("retry-max-delay must be a positive whole number of milliseconds")
	}

	if p.MaxDelay < p.InitialDelay {
		return errors.New("retry-max-delay must not be less than retry-initial-delay")
	}

	return nil
}

// NextDelay doubles the previous destination pause up to the configured cap.
func (p RetryPolicy) NextDelay(previous time.Duration) time.Duration {
	if previous < p.InitialDelay {
		return p.InitialDelay
	}

	if previous > p.MaxDelay/2 {
		return p.MaxDelay
	}

	return previous * 2
}
