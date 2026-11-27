package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// Source reads a ban source, including expired sources.
func (t *transaction) Source(ctx context.Context, ip string, kind model.SourceKind) (model.Source, bool, error) {
	source := model.Source{Kind: kind}
	var expires int64
	err := t.tx.QueryRowContext(ctx, `
SELECT expires, reason FROM ban_sources WHERE ip = ? AND kind = ?
`, ip, kind).Scan(&expires, &source.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Source{}, false, nil
	}
	if err != nil {
		return model.Source{}, false, err
	}
	source.ExpiresAt = time.UnixMilli(expires).UTC()
	return source, true, nil
}

// PutSource inserts or updates a ban source.
func (t *transaction) PutSource(ctx context.Context, ip string, source model.Source) error {
	_, err := t.tx.ExecContext(ctx, `
INSERT INTO ban_sources (ip, kind, expires, reason)
VALUES (?, ?, ?, ?)
ON CONFLICT (ip, kind) DO UPDATE SET
    expires = excluded.expires,
    reason = excluded.reason
`, ip, source.Kind, source.ExpiresAt.UnixMilli(), source.Reason)
	if err == nil {
		t.changed = true
	}
	return err
}

// Sources returns active persisted reasons for the supplied IP and time.
func (t *transaction) Sources(ctx context.Context, ip string, now time.Time) ([]model.Source, error) {
	return readBanSources(ctx, t.tx, ip, now)
}

// DeleteSources clears all independent reasons without revising the decision.
func (t *transaction) DeleteSources(ctx context.Context, ip string) error {
	result, err := t.tx.ExecContext(ctx, "DELETE FROM ban_sources WHERE ip = ?", ip)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count > 0 {
		t.changed = true
	}
	return err
}

// ExpiredSourceIPs returns affected addresses before any expired source is deleted.
func (t *transaction) ExpiredSourceIPs(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := t.tx.QueryContext(ctx, `
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

// DeleteExpiredSources removes expired ban sources.
func (t *transaction) DeleteExpiredSources(ctx context.Context, now time.Time) error {
	result, err := t.tx.ExecContext(ctx, `
DELETE FROM ban_sources WHERE expires <= ?
`, now.UnixMilli())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count > 0 {
		t.changed = true
	}
	return err
}

// Record returns a consistent decision view from this transaction.
func (t *transaction) Record(ctx context.Context, id string, now time.Time) (model.Record, error) {
	return readBan(ctx, t.tx, id, now)
}
