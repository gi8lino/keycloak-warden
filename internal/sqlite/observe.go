package sqlite

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

// RecordFailure persists a new occurrence only once per producer and identifier.
func (t *transaction) RecordFailure(ctx context.Context, event events.Event, now time.Time) (inserted bool, err error) {
	result, err := t.tx.ExecContext(ctx, `
INSERT INTO failures (source, event_id, ip, received, generation)
VALUES (?, ?, ?, ?, COALESCE((
    SELECT failure_generation
    FROM decisions
    WHERE ip = ?
), 0))
ON CONFLICT DO NOTHING
`, event.Source, event.ID, event.IP.String(), now.UnixMilli(), event.IP.String())
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

// CountFailures counts observations visible within the current transaction and window.
func (t *transaction) CountFailures(ctx context.Context, ip string, since time.Time) (count int, err error) {
	err = t.tx.QueryRowContext(ctx, `
SELECT count(*)
FROM failures
WHERE ip = ?
    AND received > ?
    AND generation = COALESCE((
        SELECT failure_generation
        FROM decisions
        WHERE ip = ?
    ), 0)
`, ip, since.UnixMilli(), ip).Scan(&count)
	return count, err
}
