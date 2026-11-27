package sqlite

import (
	"context"
	"database/sql"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// readCurrentDeliveries loads all current-revision destination statuses independently
// from the bounded, historical attempt timeline, in the decision read transaction.
func readCurrentDeliveries(ctx context.Context, tx *sql.Tx, ip string, revision int64) ([]model.Delivery, error) {
	rows, err := tx.QueryContext(
		ctx,
		`
SELECT
    h.destination,
    h.revision,
    h.desired_state,
    h.status,
    h.acknowledged_at,
    CASE WHEN h.status = 'retrying' THEN MAX(COALESCE(q.retry_at, 0), COALESCE(b.retry_at, 0)) END
FROM delivery_history AS h
LEFT JOIN deliveries AS q ON q.ip = h.ip
    AND q.destination = h.destination
LEFT JOIN destination_backoff AS b ON b.destination = h.destination
WHERE h.ip = ?
    AND h.revision = ?
ORDER BY h.destination
`,
		ip,
		revision,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	current := []model.Delivery{}
	for rows.Next() {
		var row model.Delivery
		var acknowledgedAt, retryAt sql.NullInt64
		if err := rows.Scan(
			&row.Destination,
			&row.Revision,
			&row.DesiredState,
			&row.Status,
			&acknowledgedAt,
			&retryAt,
		); err != nil {
			return nil, err
		}
		row.AcknowledgedAt = optionalTime(acknowledgedAt)
		if retryAt.Valid && retryAt.Int64 > 0 {
			row.NextAttemptAt = optionalTime(retryAt)
		}
		current = append(current, row)
	}
	return current, rows.Err()
}
