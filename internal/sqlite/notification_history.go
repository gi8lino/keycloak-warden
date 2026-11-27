package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// NotificationStats returns retained occurrence counts and the next eligible deadline.
func (s *Store) NotificationStats(ctx context.Context) (model.NotificationWorker, error) {
	var stats model.NotificationWorker
	var last sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
SELECT
    COUNT(*) FILTER (WHERE state = 'pending' AND attempts = retry_baseline),
    COUNT(*) FILTER (WHERE state = 'pending' AND attempts > retry_baseline),
    COUNT(*) FILTER (WHERE state = 'exhausted'),
    COUNT(*) FILTER (WHERE state = 'delivered'),
    (SELECT MAX(completed_at) FROM notification_attempts)
FROM notification_deliveries
`).Scan(&stats.PendingDeliveries, &stats.RetryingDeliveries, &stats.ExhaustedDeliveries, &stats.Delivered, &last)
	if err != nil {
		return model.NotificationWorker{}, err
	}
	if last.Valid {
		at := time.UnixMilli(last.Int64).UTC()
		stats.LastAttemptAt = &at
	}
	deadline, err := s.NextNotificationDeadline(ctx)
	if err != nil {
		return model.NotificationWorker{}, err
	}
	if !deadline.IsZero() {
		stats.NextDeadline = &deadline
	}
	return stats, nil
}

// ListNotifications returns the newest retained notification deliveries, with their latest known attempt.
func (s *Store) ListNotifications(ctx context.Context, before int64, limit int) ([]model.NotificationDelivery, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
    d.id, d.incident_id, d.destination,
    CASE WHEN d.state = 'pending' AND d.attempts > d.retry_baseline THEN 'retrying' ELSE d.state END,
    d.attempts, d.next_at, d.completed_at, a.completed_at, COALESCE(a.error, '')
FROM notification_deliveries AS d
LEFT JOIN notification_attempts AS a ON a.delivery_id = d.id AND a.number = d.attempts
WHERE (? = 0 OR d.id < ?)
ORDER BY d.id DESC
LIMIT ?
`, before, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	items := make([]model.NotificationDelivery, 0)
	for rows.Next() {
		var item model.NotificationDelivery
		var next int64
		var completed, last sql.NullInt64
		if err := rows.Scan(&item.ID, &item.IncidentID, &item.Destination, &item.Status, &item.Attempts, &next, &completed, &last, &item.LastError); err != nil {
			return nil, err
		}
		if !completed.Valid {
			at := time.UnixMilli(next).UTC()
			item.NextAt = &at
		} else {
			at := time.UnixMilli(completed.Int64).UTC()
			item.CompletedAt = &at
		}
		if last.Valid {
			at := time.UnixMilli(last.Int64).UTC()
			item.LastAttemptAt = &at
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListNotificationAttempts returns recorded sends without reconstructing pre-migration history.
func (s *Store) ListNotificationAttempts(ctx context.Context, id, before int64, limit int) ([]model.NotificationAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT number, completed_at, COALESCE(error, '')
FROM notification_attempts
WHERE delivery_id = ? AND (? = 0 OR number < ?)
ORDER BY number DESC
LIMIT ?
`, id, before, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	items := make([]model.NotificationAttempt, 0)
	for rows.Next() {
		var item model.NotificationAttempt
		var completed int64
		if err := rows.Scan(&item.Number, &completed, &item.Error); err != nil {
			return nil, err
		}
		item.CompletedAt = time.UnixMilli(completed).UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

// RetryNotification requeues an exhausted occurrence without deleting previous attempts.
func (s *Store) RetryNotification(ctx context.Context, id int64, actor string, identities map[string]string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var destination string
	var identity sql.NullString
	var attempts int
	err = tx.QueryRowContext(ctx, `
SELECT destination, identity, attempts
FROM notification_deliveries
WHERE id = ? AND state = 'exhausted'
`, id).Scan(&destination, &identity, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return notifications.ErrRetryConflict
	}
	if err != nil {
		return err
	}
	if !identity.Valid || identity.String == "" || identities[destination] != identity.String {
		return notifications.ErrRetryConflict
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE notification_deliveries
SET state = 'pending', retry_baseline = attempts, delay = 0, next_at = ?, completed_at = NULL
WHERE id = ?
`, now.UnixMilli(), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO notification_retries (delivery_id, previous_attempts, requested_at, actor)
VALUES (?, ?, ?, ?)
`, id, attempts, now.UnixMilli(), actor); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	wake(s.notificationChanges)
	return nil
}
