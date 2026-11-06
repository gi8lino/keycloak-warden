package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
)

// Maintain expires individual ban sources, reconciles their effective decisions, and prunes observations.
func (s *Store) Maintain(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT ip
FROM ban_sources
WHERE expires <= ?
`, now.UnixMilli())
	if err != nil {
		return err
	}
	var expired []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			_ = rows.Close()
			return err
		}
		expired = append(expired, ip)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
DELETE FROM ban_sources
WHERE expires <= ?
`, now.UnixMilli()); err != nil {
		return err
	}
	for _, ip := range expired {
		if _, err := reconcileDecision(ctx, tx, ip, now, s.targets, nil); err != nil {
			return err
		}
	}

	retain := max(24*time.Hour, s.rule.Window)
	if _, err := tx.ExecContext(ctx, `
DELETE FROM failures
WHERE received <= ?
`, now.Add(-retain).UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// Next loads the oldest pending target using its latest desired decision revision.
func (s *Store) Next(ctx context.Context, now time.Time) (*actions.Job, error) {
	var job actions.Job
	var expires int64
	decision := &job.Decision
	err := s.db.QueryRowContext(ctx, `
SELECT d.id, d.revision, d.ip, d.active, d.expires, d.failures, q.destination
FROM deliveries AS q
JOIN decisions AS d USING (ip)
WHERE q.acknowledged < d.revision
    AND q.retry_at <= ?
    AND (d.active = 0 OR d.expires > ?)
ORDER BY q.retry_at, d.expires, q.destination
LIMIT 1
`, now.UnixMilli(), now.UnixMilli()).Scan(
		&decision.ID,
		&decision.Revision,
		&decision.IP,
		&decision.Active,
		&expires,
		&decision.Failures,
		&job.Destination,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decision.ExpiresAt = time.UnixMilli(expires).UTC()

	return &job, nil
}

// Finish acknowledges successful work or schedules a retry for this destination.
func (s *Store) Finish(ctx context.Context, job actions.Job, success bool, now time.Time) error {
	if success {
		_, err := s.db.ExecContext(ctx, `
UPDATE deliveries
SET acknowledged = MAX(acknowledged, ?), retry_at = 0
WHERE ip = ? AND destination = ?
`, job.Decision.Revision, job.Decision.IP, job.Destination)
		return err
	}

	_, err := s.db.ExecContext(ctx, `
UPDATE deliveries
SET retry_at = ?
WHERE ip = ? AND destination = ?
`, now.Add(10*time.Second).UnixMilli(), job.Decision.IP, job.Destination)

	return err
}
