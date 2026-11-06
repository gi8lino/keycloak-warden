// Package detection implements the failed-login threshold policy.
package detection

import (
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

// Rule describes a sliding window of login failures keyed by canonical client IP.
type Rule struct {
	// Threshold is the minimum number of distinct matching events.
	Threshold int
	// Window is how long a received failure contributes to the count.
	Window time.Duration
	// Ban is the lifetime of the desired block since the latest qualifying failure.
	Ban time.Duration
}

// Validate rejects settings that cannot produce a bounded positive window or ban.
func (r Rule) Validate() error {
	if !r.hasValidThreshold() {
		return errors.New("threshold must be positive")
	}
	if !r.hasValidDurations() {
		return errors.New("window and ban must be at least one second")
	}
	return nil
}

// hasValidThreshold reports whether the configured threshold is positive.
func (r Rule) hasValidThreshold() bool {
	return r.Threshold > 0
}

// hasValidDurations reports whether both durations are at least one second.
func (r Rule) hasValidDurations() bool {
	return r.Window >= time.Second && r.Ban >= time.Second
}

// Matches selects Keycloak login errors that can be attributed to an address.
func (r Rule) Matches(e events.Event) bool {
	return e.Source == "keycloak" && e.Kind == "LOGIN_ERROR" && e.IP.IsValid()
}

// Triggered reports whether the observed count satisfies the configured threshold.
func (r Rule) Triggered(count int) bool {
	return count >= r.Threshold
}
