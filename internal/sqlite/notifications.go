package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// enqueueNotifications persists occurrence snapshots in the same transaction as the incident.
func (t *transaction) enqueueNotifications(ctx context.Context, incident model.Incident, destinations []string) error {
	if len(destinations) == 0 {
		return nil
	}
	payload, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	for _, destination := range destinations {
		if _, err := t.tx.ExecContext(ctx, `
INSERT INTO notification_deliveries (incident_id, destination, payload, next_at, identity)
VALUES (?, ?, ?, ?, (SELECT identity FROM notification_identities WHERE name = ?))
`, incident.ID, destination, string(payload), incident.At.UnixMilli(), destination); err != nil {
			return err
		}
	}
	t.notificationChanged = true
	return nil
}

// BindNotificationIdentities rejects removal or reassignment of destinations with pending jobs.
func (s *Store) BindNotificationIdentities(ctx context.Context, identities map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := bindNotificationIdentities(ctx, tx, identities); err != nil {
		return err
	}
	return tx.Commit()
}

// bindNotificationIdentities checks and binds occurrence destinations in the caller's transaction.
func bindNotificationIdentities(ctx context.Context, tx *sql.Tx, identities map[string]string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT n.name, n.identity
FROM notification_identities AS n
JOIN notification_deliveries AS d ON d.destination = n.name
WHERE d.state = 'pending'
ORDER BY n.name
`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, identity string
		if err := rows.Scan(&name, &identity); err != nil {
			_ = rows.Close()
			return err
		}
		if identities[name] != identity {
			_ = rows.Close()
			return fmt.Errorf("notification destination %q has pending deliveries; drain them before removal or reassignment", name)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(identities)) {
		if identities[name] == "" {
			return fmt.Errorf("notification destination %q has no identity", name)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO notification_identities (name, identity)
VALUES (?, ?)
ON CONFLICT (name) DO UPDATE SET identity = excluded.identity
`, name, identities[name]); err != nil {
			return err
		}
	}
	return nil
}

// NextNotification returns the oldest ready occurrence, preserving FIFO within each destination.
func (s *Store) NextNotification(ctx context.Context, now time.Time) (*notifications.Job, error) {
	var job notifications.Job
	var payload string
	var delay int64
	err := s.db.QueryRowContext(ctx, `
SELECT d.id, d.destination, d.payload, d.attempts, d.delay, d.retry_baseline
FROM notification_deliveries AS d
WHERE d.state = 'pending'
    AND d.next_at <= ?
    AND NOT EXISTS (
        SELECT 1
        FROM notification_deliveries AS older
        WHERE older.destination = d.destination
            AND older.state = 'pending'
            AND older.id < d.id
    )
ORDER BY d.next_at, d.id
LIMIT 1
`, now.UnixMilli()).Scan(&job.ID, &job.Destination, &payload, &job.Attempts, &delay, &job.RetryBaseline)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(payload), &job.Incident); err != nil {
		return nil, fmt.Errorf("decode persisted notification %d: %w", job.ID, err)
	}
	job.Delay = time.Duration(delay) * time.Millisecond
	return &job, nil
}

// NextNotificationDeadline returns the earliest head-of-queue deadline across destinations.
func (s *Store) NextNotificationDeadline(ctx context.Context) (time.Time, error) {
	var deadline sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
SELECT MIN(d.next_at)
FROM notification_deliveries AS d
WHERE d.state = 'pending'
    AND NOT EXISTS (
        SELECT 1
        FROM notification_deliveries AS older
        WHERE older.destination = d.destination
            AND older.state = 'pending'
            AND older.id < d.id
    )
`).Scan(&deadline)
	if err != nil || !deadline.Valid {
		return time.Time{}, err
	}
	return time.UnixMilli(deadline.Int64).UTC(), nil
}

// FinishNotification persists the application's completed attempt or retry outcome.
func (s *Store) FinishNotification(ctx context.Context, job notifications.Job, completion notifications.Completion) error {
	var completed any
	if !completion.CompletedAt.IsZero() {
		completed = completion.CompletedAt.UnixMilli()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(
		ctx,
		`
UPDATE notification_deliveries
SET attempts = ?,
    state = ?,
    next_at = ?,
    delay = ?,
    completed_at = ?
WHERE id = ?
    AND state = 'pending'
    AND attempts = ?
    AND retry_baseline = ?
`,
		completion.Attempts,
		completion.State,
		completion.NextAt.UnixMilli(),
		completion.Delay.Milliseconds(),
		completed,
		job.ID,
		job.Attempts,
		job.RetryBaseline,
	)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("notification job changed before completion")
	}
	if completion.Attempted {
		var message any
		if completion.Error != "" {
			message = completion.Error
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO notification_attempts (delivery_id, number, completed_at, error)
VALUES (?, ?, ?, ?)
`, job.ID, completion.Attempts, completion.At.UnixMilli(), message); err != nil {
			return err
		}
	}
	return tx.Commit()
}
