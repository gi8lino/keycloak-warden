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

// banTx implements the domain's persistence primitives inside a SQLite transaction.
type banTx struct {
	// tx contains all source and decision changes until the owner commits.
	tx *sql.Tx
	// changed requests a post-commit worker wakeup for source or state changes.
	changed bool
}

// EnsureDecision creates a stable UUIDv7 identity before attaching ban sources.
func (b banTx) EnsureDecision(ctx context.Context, ip string) error {
	_, err := b.tx.ExecContext(ctx, `
INSERT INTO decisions (ip, id, revision, active, expires)
VALUES (?, ?, 0, 0, 0)
ON CONFLICT (ip) DO NOTHING
`, ip, uuid.NewV7().String())
	return err
}

// Source reads the existing expiry and reason without applying domain policy.
func (b banTx) Source(ctx context.Context, ip string, kind bans.SourceKind) (bans.Source, bool, error) {
	source := bans.Source{Kind: kind}
	var expires int64
	err := b.tx.QueryRowContext(ctx, `
SELECT expires, reason FROM ban_sources WHERE ip = ? AND kind = ?
`, ip, kind).Scan(&expires, &source.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return bans.Source{}, false, nil
	}
	if err != nil {
		return bans.Source{}, false, err
	}
	source.ExpiresAt = time.UnixMilli(expires).UTC()
	return source, true, nil
}

// PutSource writes the already-resolved source without altering its expiry.
func (b *banTx) PutSource(ctx context.Context, ip string, source bans.Source) error {
	_, err := b.tx.ExecContext(ctx, `
INSERT INTO ban_sources (ip, kind, expires, reason)
VALUES (?, ?, ?, ?)
ON CONFLICT (ip, kind) DO UPDATE SET
    expires = excluded.expires,
    reason = excluded.reason
`, ip, source.Kind, source.ExpiresAt.UnixMilli(), source.Reason)
	if err == nil {
		b.changed = true
	}
	return err
}

// Decision reads the materialized current state for a given IP.
func (b banTx) Decision(ctx context.Context, ip string) (decisions.Decision, error) {
	return readDecisionByIP(ctx, b.tx, ip)
}

// Sources returns active persisted reasons for the supplied IP and time.
func (b banTx) Sources(ctx context.Context, ip string, now time.Time) ([]bans.Source, error) {
	return readBanSources(ctx, b.tx, ip, now)
}

// SaveDecision stores calculated policy output and synchronizes destination work.
func (b *banTx) SaveDecision(ctx context.Context, previous, decision decisions.Decision, changed bool, targets []string) error {
	if changed {
		b.changed = true
		if _, err := b.tx.ExecContext(ctx, `
UPDATE decisions
SET revision = ?, active = ?, expires = ?
WHERE ip = ?
`, decision.Revision, decision.State == decisions.StateBanned,
			decision.ExpiresAt.UnixMilli(), decision.IP); err != nil {
			return err
		}
	}

	// A fully acknowledged release no longer owns a destination, whereas an
	// unacknowledged release must remain queued until accepted externally.
	if _, err := b.tx.ExecContext(ctx, `
DELETE FROM deliveries
WHERE ip = ? AND acknowledged = ? AND ? = 1
`, decision.IP, previous.Revision, previous.State == decisions.StateUnbanned); err != nil {
		return err
	}

	for _, name := range targets {
		if _, err := b.tx.ExecContext(ctx, `
INSERT INTO deliveries (ip, destination)
VALUES (?, ?)
ON CONFLICT (ip, destination) DO NOTHING
`, decision.IP, name); err != nil {
			return err
		}
	}
	return syncDeliveryHistory(ctx, b.tx, decision)
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

// DecisionByID reads the current decision identified by its stable ID.
func (b *banTx) DecisionByID(ctx context.Context, id string) (decisions.Decision, error) {
	decision, err := readDecision(ctx, b.tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return decisions.Decision{}, bans.ErrNotFound
	}
	return decision, err
}

// DeleteSources clears all independent reasons without revising the decision.
func (b *banTx) DeleteSources(ctx context.Context, ip string) error {
	result, err := b.tx.ExecContext(ctx, "DELETE FROM ban_sources WHERE ip = ?", ip)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count > 0 {
		b.changed = true
	}
	return err
}

// ResetFailures advances the observation generation while retaining producer IDs.
func (b *banTx) ResetFailures(ctx context.Context, ip string) error {
	_, err := b.tx.ExecContext(ctx, `
UPDATE decisions
SET failure_generation = failure_generation + 1
WHERE ip = ?
`, ip)
	if err == nil {
		b.changed = true
	}
	return err
}

// ExpiredSourceIPs returns affected addresses before any expired source is deleted.
func (b *banTx) ExpiredSourceIPs(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := b.tx.QueryContext(ctx, `
SELECT DISTINCT ip FROM ban_sources WHERE expires <= ?
`, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	return ips, rows.Close()
}

// DeleteExpiredSources removes elapsed reasons without choosing the new ban state.
func (b *banTx) DeleteExpiredSources(ctx context.Context, now time.Time) error {
	result, err := b.tx.ExecContext(ctx, `
DELETE FROM ban_sources WHERE expires <= ?
`, now.UnixMilli())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count > 0 {
		b.changed = true
	}
	return err
}

// Record returns a consistent decision view from this transaction.
func (b *banTx) Record(ctx context.Context, id string, now time.Time) (bans.Record, error) {
	return readBan(ctx, b.tx, id, now)
}
