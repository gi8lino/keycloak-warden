package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Maintain expires sources and returns only effective releases after commit.
func (s *Store) Maintain(ctx context.Context, now time.Time, targets []string) ([]decisions.Decision, error) {
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
		decision, changed, err := bans.ReconcileDecision(ctx, &banTx{tx: tx}, ip, now, targets)
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
func (s *Store) Prune(ctx context.Context, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM failures
WHERE received <= ?
`, cutoff.UnixMilli())
	return err
}

// Next loads the oldest pending target using its latest desired decision revision.
func (s *Store) Next(ctx context.Context, now time.Time) (*actions.Job, error) {
	var job actions.Job
	var expires int64
	var active bool
	var previousDelayMillis int64
	decision := &job.Decision
	err := s.db.QueryRowContext(ctx, `
SELECT d.id, d.revision, d.ip, d.active, d.expires, q.destination, COALESCE(b.delay_ms, 0)
FROM deliveries AS q
JOIN decisions AS d USING (ip)
JOIN delivery_history AS h ON h.ip = q.ip AND h.destination = q.destination AND h.revision = d.revision
LEFT JOIN destination_backoff AS b ON b.destination = q.destination
WHERE q.acknowledged < d.revision
    AND h.status IN ('pending', 'retrying')
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
		&previousDelayMillis,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	job.PreviousDelay = time.Duration(previousDelayMillis) * time.Millisecond
	decision.State = stateFromActive(active)
	decision.ExpiresAt = time.UnixMilli(expires).UTC()

	return &job, nil
}

// Finish atomically records an attempt and acknowledges or retries within the supplied limit.
func (s *Store) Finish(
	ctx context.Context,
	job actions.Job,
	deliveryErr error,
	limit int,
	now time.Time,
	retryDelay time.Duration,
) error {
	if limit < 1 {
		return errors.New("max-attempts must be at least 1")
	}
	if deliveryErr != nil && retryDelay <= 0 {
		return errors.New("retry delay must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := recordAttempt(ctx, tx, job, deliveryErr, now); err != nil {
		return err
	}

	if deliveryErr != nil {
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

	if deliveryErr == nil {
		err = acknowledgeDelivery(ctx, tx, job)
	} else {
		err = scheduleRetry(ctx, tx, job, now, retryDelay)
		if err == nil {
			err = applyAttemptLimit(ctx, tx, job.Destination, limit, job.Decision.IP, job.Decision.Revision)
		}
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

// scheduleRetry persists the pause calculated by the application and delays this job.
func scheduleRetry(
	ctx context.Context,
	tx *sql.Tx,
	job actions.Job,
	now time.Time,
	delay time.Duration,
) error {
	retryAt := now.Add(delay).UnixMilli()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO destination_backoff (destination, delay_ms, retry_at) VALUES (?, ?, ?)
ON CONFLICT (destination) DO UPDATE SET delay_ms = excluded.delay_ms, retry_at = excluded.retry_at
`, job.Destination, delay.Milliseconds(), retryAt); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE deliveries SET retry_at = ? WHERE ip = ? AND destination = ?", retryAt, job.Decision.IP, job.Destination)
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
    JOIN delivery_history AS h ON h.ip = q.ip AND h.destination = q.destination AND h.revision = d.revision
    LEFT JOIN destination_backoff AS b ON b.destination = q.destination
    WHERE q.acknowledged < d.revision
        AND h.status IN ('pending', 'retrying')
)`).Scan(&due)
	if err != nil || !due.Valid {
		return time.Time{}, err
	}
	return time.UnixMilli(due.Int64), nil
}
