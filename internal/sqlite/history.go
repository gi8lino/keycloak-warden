package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// syncDeliveryHistory registers queued destinations and retires unfinished earlier revisions.
func syncDeliveryHistory(ctx context.Context, tx *sql.Tx, d decisions.Decision) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE delivery_history
SET status = 'superseded', superseded_by = ?
WHERE ip = ? AND revision < ? AND status IN ('pending', 'retrying')
`, d.Revision, d.IP, d.Revision); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO delivery_history (ip, revision, destination, desired_state, status)
SELECT ip, ?, destination, ?, 'pending'
FROM deliveries WHERE ip = ?
ON CONFLICT DO NOTHING
`, d.Revision, d.State, d.IP)
	return err
}

// recordAttempt stores a completed call and its delivery status within the queue transaction.
func recordAttempt(ctx context.Context, tx *sql.Tx, job actions.Job, deliveryErr error, now time.Time) error {
	d := job.Decision
	var message *string
	if deliveryErr != nil {
		diagnostic := deliveryErr.Error()
		message = &diagnostic
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO delivery_attempts (ip, revision, destination, number, completed_at, error)
SELECT ?, ?, ?, COALESCE(MAX(number), 0) + 1, ?, ?
FROM delivery_attempts WHERE ip = ? AND revision = ? AND destination = ?
`, d.IP, d.Revision, job.Destination, now.UnixMilli(), message, d.IP, d.Revision, job.Destination); err != nil {
		return err
	}

	if deliveryErr != nil {
		_, err := tx.ExecContext(ctx, `
UPDATE delivery_history SET status = 'retrying'
WHERE ip = ? AND revision = ? AND destination = ? AND status = 'pending'
`, d.IP, d.Revision, job.Destination)
		return err
	}
	_, err := tx.ExecContext(ctx, `
UPDATE delivery_history SET status = 'delivered', acknowledged_at = ?, superseded_by = NULL
WHERE ip = ? AND revision = ? AND destination = ?
`, now.UnixMilli(), d.IP, d.Revision, job.Destination)
	return err
}

// readDeliveryHistory groups completed attempts under their revision in a single snapshot.
func readDeliveryHistory(ctx context.Context, tx *sql.Tx, ip string) ([]decisions.Delivery, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT h.destination, h.revision, COALESCE(h.desired_state, ''), h.status,
       h.acknowledged_at, COALESCE(h.superseded_by, 0),
       CASE WHEN h.status = 'retrying' THEN MAX(q.retry_at, COALESCE(b.retry_at, 0)) END,
       a.number, a.completed_at, a.error
FROM delivery_history h
LEFT JOIN delivery_attempts a USING (ip, revision, destination)
LEFT JOIN deliveries q USING (ip, destination)
LEFT JOIN destination_backoff b USING (destination)
WHERE h.ip = ?
ORDER BY h.revision DESC, h.destination, a.number
`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var history []decisions.Delivery
	for rows.Next() {
		var d decisions.Delivery
		var acknowledged, retry, number, completed sql.NullInt64
		var message sql.NullString
		if err := rows.Scan(
			&d.Destination,
			&d.Revision,
			&d.DesiredState,
			&d.Status,
			&acknowledged,
			&d.SupersededByRevision,
			&retry,
			&number,
			&completed,
			&message,
		); err != nil {
			return nil, err
		}
		if startsNewDelivery(history, d) {
			d.AcknowledgedAt = optionalTime(acknowledged)
			d.NextAttemptAt = optionalTime(retry)
			history = append(history, d)
		}
		if number.Valid {
			attempt := decisions.DeliveryAttempt{
				Number:  number.Int64,
				At:      time.UnixMilli(completed.Int64).UTC(),
				Outcome: "succeeded",
			}
			if message.Valid {
				attempt.Outcome = "failed"
				attempt.Error = message.String
			}
			last := &history[len(history)-1]
			last.Attempts = append(last.Attempts, attempt)
		}
	}
	return history, rows.Err()
}

// startsNewDelivery reports whether the row begins a new revision or destination group.
func startsNewDelivery(history []decisions.Delivery, row decisions.Delivery) bool {
	if len(history) == 0 {
		return true
	}

	previous := history[len(history)-1]
	return previous.Revision != row.Revision || previous.Destination != row.Destination
}

// optionalTime converts a stored SQLite timestamp without inventing missing dates.
func optionalTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	t := time.UnixMilli(value.Int64).UTC()
	return &t
}
