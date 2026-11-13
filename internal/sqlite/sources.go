package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"uuid"
)

// ensureDecision creates a stable UUIDv7 identity before attaching independently expiring ban sources.
func ensureDecision(ctx context.Context, tx *sql.Tx, ip string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO decisions (ip, id, revision, active, expires)
VALUES (?, ?, 0, 0, 0)
ON CONFLICT (ip) DO NOTHING
`, ip, uuid.NewV7().String())
	return err
}

// setSource persists one source after applying the domain's non-shortening expiry policy.
func setSource(
	ctx context.Context,
	tx *sql.Tx,
	ip string,
	kind bans.SourceKind,
	until time.Time,
	reason string,
) error {
	var previous int64
	err := tx.QueryRowContext(ctx, `
SELECT expires FROM ban_sources WHERE ip = ? AND kind = ?
`, ip, kind).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		until = bans.ExtendExpiry(time.UnixMilli(previous), until)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO ban_sources (ip, kind, expires, reason)
VALUES (?, ?, ?, ?)
ON CONFLICT (ip, kind) DO UPDATE SET
    expires = excluded.expires,
    reason = excluded.reason
`, ip, kind, until.UnixMilli(), reason)
	return err
}

// reconcileDecision loads independent sources, evaluates the domain policy and persists material changes.
func reconcileDecision(
	ctx context.Context,
	tx *sql.Tx,
	ip string,
	now time.Time,
	targets []string,
) (decision decisions.Decision, changed bool, err error) {
	previous, err := readDecisionByIP(ctx, tx, ip)
	if err != nil {
		return decisions.Decision{}, false, err
	}
	sources, err := readBanSources(ctx, tx, ip, now)
	if err != nil {
		return decisions.Decision{}, false, err
	}

	decision, changed = bans.Reconcile(previous, sources, now)
	if changed {
		if _, err := tx.ExecContext(ctx, `
UPDATE decisions
SET revision = ?, active = ?, expires = ?
WHERE ip = ?
`, decision.Revision, decision.State == decisions.StateBanned,
			decision.ExpiresAt.UnixMilli(), ip); err != nil {
			return decisions.Decision{}, false, err
		}
	}

	// Retire fully acknowledged releases before a later ban can reuse this IP.
	// Outstanding releases retain ownership until their provider acknowledges them.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM deliveries
WHERE ip = ? AND acknowledged = ? AND ? = 1
`, ip, previous.Revision, previous.State == decisions.StateUnbanned); err != nil {
		return decisions.Decision{}, false, err
	}

	for _, name := range targets {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO deliveries (ip, destination)
VALUES (?, ?)
ON CONFLICT (ip, destination) DO NOTHING
`, ip, name); err != nil {
			return decisions.Decision{}, false, err
		}
	}
	return decision, changed, nil
}

// readDecisionByIP loads the current materialized decision within the transaction.
func readDecisionByIP(ctx context.Context, tx *sql.Tx, ip string) (decisions.Decision, error) {
	var result decisions.Decision
	var active bool
	var expires int64
	err := tx.QueryRowContext(ctx, `
SELECT id, revision, active, expires FROM decisions WHERE ip = ?
`, ip).Scan(&result.ID, &result.Revision, &active, &expires)
	if err != nil {
		return decisions.Decision{}, err
	}
	result.IP = ip
	result.State = stateFromActive(active)
	result.ExpiresAt = time.UnixMilli(expires).UTC()
	return result, nil
}
