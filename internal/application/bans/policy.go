package bans

import (
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// ExtendExpiry keeps the later deadline when an independent ban source is renewed.
func ExtendExpiry(existing, requested time.Time) time.Time {
	if existing.After(requested) {
		return existing
	}
	return requested
}

// Reconcile computes the desired decision from independent active sources.
// It increments the revision only when a field delivered to destinations changes.
// The last expiry is retained on release for historical inspection.
func Reconcile(
	previous decisions.Decision,
	sources []Source,
	now time.Time,
) (decisions.Decision, bool) {
	next := previous
	var until time.Time
	for _, source := range sources {
		if source.ExpiresAt.After(now) {
			until = ExtendExpiry(until, source.ExpiresAt)
		}
	}

	if until.IsZero() {
		next.State = decisions.StateUnbanned
	} else {
		next.State = decisions.StateBanned
		next.ExpiresAt = until.UTC()
	}

	changed := hasChanged(previous, next)
	if changed {
		next.Revision++
	}
	return next, changed
}

// hasChanged prüft, ob sich relevante Felder zwischen zwei Decisions unterscheiden.
func hasChanged(previous, next decisions.Decision) bool {
	return next.State != previous.State ||
		!next.ExpiresAt.Equal(previous.ExpiresAt)
}
