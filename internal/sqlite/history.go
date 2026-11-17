package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
)

// syncDeliveryHistory registers queued destinations and retires unfinished earlier revisions.
func syncDeliveryHistory(ctx context.Context, tx *sql.Tx, d decisions.Decision) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE delivery_history
SET status = ?, superseded_by = ?
WHERE ip = ? AND revision < ? AND status IN ('pending', 'retrying')
`, deliverystate.StatusSuperseded, d.Revision, d.IP, d.Revision); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO delivery_history (ip, revision, destination, desired_state, status)
SELECT ip, ?, destination, ?, ?
FROM deliveries WHERE ip = ?
ON CONFLICT DO NOTHING
`, d.Revision, d.State, deliverystate.StatusPending, d.IP)
	return err
}

// recordAttempt stores a completed call and its delivery status within the queue transaction.
func recordAttempt(
	ctx context.Context,
	tx *sql.Tx,
	job actions.Job,
	deliveryErr error,
	now time.Time,
) error {
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

	return nil
}

// finishAttemptStatus marks only the current revision as retrying or delivered.
// A stale provider response remains recorded as an attempt but never changes
// the superseded revision's status or current destination scheduling.
func finishAttemptStatus(
	ctx context.Context,
	tx *sql.Tx,
	job actions.Job,
	deliveryErr error,
	now time.Time,
) error {
	if deliveryErr != nil {
		_, err := tx.ExecContext(ctx, `
UPDATE delivery_history SET status = ?
WHERE ip = ? AND revision = ? AND destination = ? AND status IN ('pending', 'retrying')
`, deliverystate.StatusRetrying, job.Decision.IP, job.Decision.Revision, job.Destination)
		return err
	}
	_, err := tx.ExecContext(ctx, `
UPDATE delivery_history
SET status = ?, acknowledged_at = ?, superseded_by = NULL
WHERE ip = ? AND revision = ? AND destination = ?
`, deliverystate.StatusDelivered, now.UnixMilli(), job.Decision.IP, job.Decision.Revision, job.Destination)
	return err
}

// readDeliveryHistory loads at most one bounded page of destination/revision groups.
// Completed attempts are retained in SQLite but only the most recent 16 per
// group are included in the HTTP inspection view. Paging does not delete history.
func readDeliveryHistory(
	ctx context.Context,
	tx *sql.Tx,
	ip string,
	page bans.HistoryPage,
) ([]decisions.Delivery, bool, error) {
	rows, err := tx.QueryContext(ctx, `
WITH page AS (
    SELECT revision, destination
    FROM delivery_history
    WHERE ip = ? AND revision <= ?
    ORDER BY revision DESC, destination
    LIMIT ? OFFSET ?
)
SELECT h.destination, h.revision, COALESCE(h.desired_state, ''), h.status,
       h.acknowledged_at, COALESCE(h.superseded_by, 0),
       CASE WHEN h.status = 'retrying' THEN MAX(q.retry_at, COALESCE(b.retry_at, 0)) END,
       a.number, a.completed_at, SUBSTR(a.error, 1, ?)
FROM page AS p
JOIN delivery_history AS h ON h.ip = ? AND h.revision = p.revision AND h.destination = p.destination
LEFT JOIN delivery_attempts AS a ON a.ip = h.ip AND a.revision = h.revision
    AND a.destination = h.destination AND a.number > (
        SELECT COALESCE(MAX(number), 0) - ?
        FROM delivery_attempts
        WHERE ip = h.ip AND revision = h.revision AND destination = h.destination
    )
LEFT JOIN deliveries AS q ON q.ip = h.ip AND q.destination = h.destination
LEFT JOIN destination_backoff AS b ON b.destination = h.destination
ORDER BY h.revision DESC, h.destination, a.number
`, ip, page.ThroughRevision, page.Groups+1, page.Offset, page.ErrorCharacters, ip, page.Attempts)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close() //nolint:errcheck

	history := make([]decisions.Delivery, 0, page.Groups)
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
			return nil, false, err
		}

		if startsNewDelivery(history, d) {
			if len(history) == page.Groups {
				return history, true, rows.Err()
			}
			d.AcknowledgedAt = optionalTime(acknowledged)
			d.NextAttemptAt = optionalTime(retry)
			history = append(history, d)
		}
		if number.Valid {
			attempt := decisions.DeliveryAttempt{
				Number:  number.Int64,
				At:      time.UnixMilli(completed.Int64).UTC(),
				Outcome: deliverystate.OutcomeSucceeded,
			}
			if message.Valid {
				attempt.Outcome = deliverystate.OutcomeFailed
				attempt.Error = message.String
			}
			last := &history[len(history)-1]
			if len(last.Attempts) == 0 && number.Int64 > 1 {
				last.AttemptsTruncated = true
			}
			last.Attempts = append(last.Attempts, attempt)
		}
	}
	return history, false, rows.Err()
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
