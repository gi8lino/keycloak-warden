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

// Reconcile derives effective ban state and revises it only when delivered fields change.
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
		// Preserve the last expiry for historical inspection after release.
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

// hasChanged reports whether the externally delivered fields of a decision differ.
func hasChanged(previous, next decisions.Decision) bool {
	return next.State != previous.State ||
		!next.ExpiresAt.Equal(previous.ExpiresAt)
}
