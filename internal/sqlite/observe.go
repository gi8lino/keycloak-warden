package sqlite

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/pkg/model"
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

// ResetFailures advances the observation generation while retaining producer IDs.
func (t *transaction) ResetFailures(ctx context.Context, ip string) error {
	_, err := t.tx.ExecContext(ctx, `
UPDATE decisions
SET failure_generation = failure_generation + 1
WHERE ip = ?
`, ip)
	if err == nil {
		t.changed = true
	}
	return err
}

// RecordObservation stores the hypothetical result without creating a decision or delivery.
func (t *transaction) RecordObservation(ctx context.Context, item model.Observation) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO ban_observations (source, event_id, ip, observed_at, expires, failures, threshold) VALUES (?, ?, ?, ?, ?, ?, ?)`, item.Source, item.EventID, item.IP, item.At.UnixMilli(), item.ExpiresAt.UnixMilli(), item.Failures, item.Threshold)
	return err
}
