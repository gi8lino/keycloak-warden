package notifications

import (
	"strings"
	"time"
	"unicode"
)

const (
	// Pending indicates that the occurrence still requires delivery.
	Pending = "pending"
	// Delivered indicates that the receiver acknowledged the occurrence.
	Delivered = "delivered"
	// Exhausted indicates that no further attempts remain.
	Exhausted = "exhausted"
)

// Completion describes the next persisted state after a delivery attempt.
type Completion struct {
	// Attempts counts completed sends.
	Attempts int
	// Attempted reports whether an outbound send actually took place.
	Attempted bool
	// At records when the attempt or budget reconciliation completed.
	At time.Time
	// Error is the bounded diagnostic of an unsuccessful send.
	Error string
	// State is the resulting delivery status.
	State string
	// Delay is the persisted retry pause, zero for terminal jobs.
	Delay time.Duration
	// NextAt is the next eligible attempt time or the terminal completion time.
	NextAt time.Time
	// CompletedAt is zero while the occurrence remains pending.
	CompletedAt time.Time
}

// Complete determines the next notification state without performing storage operations.
func Complete(job Job, deliveryErr error, limit int, now time.Time, delay time.Duration) Completion {
	result := Completion{
		Attempts: job.Attempts,
		State:    Pending,
		At:       now,
		NextAt:   now,
	}
	if job.Attempts-job.RetryBaseline < limit {
		result.Attempts++
		result.Attempted = true
	}
	if deliveryErr != nil {
		result.Error = safeError(deliveryErr)
	}
	switch {
	case result.Attempted && deliveryErr == nil:
		result.State = Delivered
	case result.Attempts-job.RetryBaseline >= limit:
		result.State = Exhausted
	default:
		result.Delay = delay
		result.NextAt = now.Add(delay)
		return result
	}
	result.CompletedAt = now
	return result
}

// safeError bounds provider diagnostics and strips control characters.
func safeError(err error) string {
	message := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	if strings.TrimSpace(message) == "" {
		return "delivery failed"
	}
	runes := []rune(message)
	if len(runes) > 512 {
		runes = runes[:512]
	}
	return string(runes)
}
