package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/google/uuid"
)

// ensureDecision creates a stable identity before attaching independently expiring ban sources.
func ensureDecision(ctx context.Context, tx *sql.Tx, ip string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO decisions (ip, id, revision, active, expires, failures)
VALUES (?, ?, 0, 0, 0, 0)
ON CONFLICT (ip) DO NOTHING
`, ip, uuid.NewString())
	return err
}

// setSource inserts or extends one block reason without shortening an existing expiry.
func setSource(
	ctx context.Context,
	tx *sql.Tx,
	ip string,
	kind bans.SourceKind,
	until time.Time,
	reason string,
) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO ban_sources (ip, kind, expires, reason)
VALUES (?, ?, ?, ?)
ON CONFLICT (ip, kind) DO UPDATE SET
    expires = MAX(ban_sources.expires, excluded.expires),
    reason = excluded.reason
`, ip, kind, until.UnixMilli(), reason)
	return err
}

// reconcileDecision materializes the union of unexpired sources and enqueues its revision.
func reconcileDecision(
	ctx context.Context,
	tx *sql.Tx,
	ip string,
	now time.Time,
	targets []string,
	failures *int,
) (decision decisions.Decision, err error) {
	var effectiveUntil int64
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(expires), 0)
FROM ban_sources
WHERE ip = ? AND expires > ?
`, ip, now.UnixMilli()).Scan(&effectiveUntil); err != nil {
		return decisions.Decision{}, err
	}

	var previousExpires int64
	var previousInactive bool
	decision = decisions.Decision{IP: ip}
	if err := tx.QueryRowContext(ctx, `
SELECT id, revision, expires, failures, NOT active
FROM decisions
WHERE ip = ?
`, ip).Scan(&decision.ID, &decision.Revision, &previousExpires, &decision.Failures, &previousInactive); err != nil {
		return decisions.Decision{}, err
	}

	decision.Active = effectiveUntil > 0
	if !decision.Active {
		effectiveUntil = previousExpires
	}
	if failures != nil {
		decision.Failures = *failures
	}
	decision.Revision++
	decision.ExpiresAt = time.UnixMilli(effectiveUntil).UTC()

	if _, err := tx.ExecContext(ctx, `
UPDATE decisions
SET revision = ?, active = ?, expires = ?, failures = ?
WHERE ip = ?
`, decision.Revision, decision.Active, effectiveUntil, decision.Failures, ip); err != nil {
		return decisions.Decision{}, err
	}

	// Retire fully acknowledged releases before a later ban can reuse this IP.
	// Outstanding releases retain ownership until their provider acknowledges them.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM deliveries
WHERE ip = ? AND acknowledged = ?
    AND ? = 1
`, ip, decision.Revision-1, previousInactive); err != nil {
		return decisions.Decision{}, err
	}

	for _, name := range targets {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO deliveries (ip, destination)
VALUES (?, ?)
ON CONFLICT (ip, destination) DO NOTHING
`, ip, name); err != nil {
			return decisions.Decision{}, err
		}
	}

	return decision, nil
}
