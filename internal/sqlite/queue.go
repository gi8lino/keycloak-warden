package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Maintain expires sources and returns only effective releases after commit.
func (s *Store) Maintain(ctx context.Context, now time.Time) ([]decisions.Decision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	expiredIPs, err := readExpiredSourceIPs(ctx, tx, now)
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
DELETE FROM ban_sources
WHERE expires <= ?
`, now.UnixMilli()); err != nil {
		return nil, err
	}

	var released []decisions.Decision
	for _, ip := range expiredIPs {
		decision, changed, err := reconcileDecision(ctx, tx, ip, now, s.targets)
		if err != nil {
			return nil, err
		}
		if changed && decision.State == decisions.StateUnbanned {
			released = append(released, decision)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return released, nil
}

// readExpiredSourceIPs finds affected addresses before their expired sources are deleted.
func readExpiredSourceIPs(ctx context.Context, tx *sql.Tx, now time.Time) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT ip
FROM ban_sources
WHERE expires <= ?
`, now.UnixMilli())
	if err != nil {
		return nil, err
	}

	var expiredIPs []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			_ = rows.Close()
			return nil, err
		}
		expiredIPs = append(expiredIPs, ip)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return expiredIPs, nil
}

// Prune removes old observations independently of delivery activity.
func (s *Store) Prune(ctx context.Context, now time.Time) error {
	retain := max(24*time.Hour, s.rule.Window)
	_, err := s.db.ExecContext(ctx, `
DELETE FROM failures
WHERE received <= ?
`, now.Add(-retain).UnixMilli())
	return err
}

// Next loads the oldest pending target using its latest desired decision revision.
func (s *Store) Next(ctx context.Context, now time.Time) (*actions.Job, error) {
	var job actions.Job
	var expires int64
	var active bool
	decision := &job.Decision
	err := s.db.QueryRowContext(ctx, `
SELECT d.id, d.revision, d.ip, d.active, d.expires, q.destination
FROM deliveries AS q
JOIN decisions AS d USING (ip)
LEFT JOIN destination_backoff AS b ON b.destination = q.destination
WHERE q.acknowledged < d.revision
    AND COALESCE(b.retry_at, 0) <= ?
    AND q.retry_at <= ?
    AND (d.active = 0 OR d.expires > ?)
ORDER BY q.retry_at, d.expires, q.destination
LIMIT 1
`, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()).Scan(
		&decision.ID,
		&decision.Revision,
		&decision.IP,
		&active,
		&expires,
		&job.Destination,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decision.State = stateFromActive(active)
	decision.ExpiresAt = time.UnixMilli(expires).UTC()

	return &job, nil
}

// Finish acknowledges successful work or schedules a retry for this destination.
func (s *Store) Finish(ctx context.Context, job actions.Job, success bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if !success {
		// A newer decision may have been committed while the provider was called.
		// Never delay that revision because delivery of an older one failed.
		var revision int64
		if err := tx.QueryRowContext(ctx, "SELECT revision FROM decisions WHERE ip = ?", job.Decision.IP).Scan(&revision); err != nil {
			return err
		}
		if revision != job.Decision.Revision {
			return tx.Commit()
		}
	}

	if success {
		err = acknowledgeDelivery(ctx, tx, job)
	} else {
		err = scheduleRetry(ctx, tx, job, now)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// acknowledgeDelivery marks the delivered revision and resets its destination's backoff.
func acknowledgeDelivery(ctx context.Context, tx *sql.Tx, job actions.Job) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE deliveries
SET acknowledged = MAX(acknowledged, ?), retry_at = 0
WHERE ip = ? AND destination = ?
`, job.Decision.Revision, job.Decision.IP, job.Destination); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM destination_backoff WHERE destination = ?", job.Destination)
	return err
}

// scheduleRetry pauses the destination and lets other queued IPs go first when it resumes.
func scheduleRetry(ctx context.Context, tx *sql.Tx, job actions.Job, now time.Time) error {
	const firstDelay = 10 * time.Second
	const maxDelay = 5 * time.Minute

	var previousMillis int64
	err := tx.QueryRowContext(ctx, "SELECT delay_ms FROM destination_backoff WHERE destination = ?", job.Destination).Scan(&previousMillis)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	delay := min(maxDelay.Milliseconds(), max(firstDelay.Milliseconds(), 2*previousMillis))
	retryAt := now.UnixMilli() + delay

	if _, err := tx.ExecContext(ctx, `
INSERT INTO destination_backoff (destination, delay_ms, retry_at) VALUES (?, ?, ?)
ON CONFLICT (destination) DO UPDATE SET delay_ms = excluded.delay_ms, retry_at = excluded.retry_at
`, job.Destination, delay, retryAt); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE deliveries SET retry_at = ? WHERE ip = ? AND destination = ?", retryAt, job.Decision.IP, job.Destination)
	return err
}

// NextDeadline returns the earliest source expiry or eligible delivery time, or zero when idle.
func (s *Store) NextDeadline(ctx context.Context) (deadline time.Time, err error) {
	var due sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
SELECT MIN(deadline)
FROM (
    SELECT MIN(expires) AS deadline
    FROM ban_sources

    UNION ALL

    SELECT MIN(MAX(q.retry_at, COALESCE(b.retry_at, 0))) AS deadline
    FROM deliveries AS q
    JOIN decisions AS d USING (ip)
    LEFT JOIN destination_backoff AS b ON b.destination = q.destination
    WHERE q.acknowledged < d.revision
)`).Scan(&due)
	if err != nil || !due.Valid {
		return time.Time{}, err
	}
	return time.UnixMilli(due.Int64), nil
}
