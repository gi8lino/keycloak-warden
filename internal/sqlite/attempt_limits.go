package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// attemptStatusUpdate is a calculated status update for a persisted delivery.
type attemptStatusUpdate struct {
	// ip identifies the address selected by the operation.
	ip string
	// revision identifies the delivery version whose status will change.
	revision int64
	// status is the outcome computed by the application attempt policy.
	status model.DeliveryStatus
}

// ReconcileAttemptLimit re-evaluates unfinished current revisions during startup.
// The application policy determines each status; SQLite applies them atomically.
func (s *Store) ReconcileAttemptLimit(ctx context.Context, name string, limit int) error {
	if limit < 1 {
		return errors.New("max-attempts must be at least 1")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
SELECT h.ip, h.revision, COALESCE(MAX(a.number), 0) - COALESCE((
    SELECT r.previous_attempts FROM delivery_retries AS r
    WHERE r.ip = h.ip AND r.revision = h.revision AND r.destination = h.destination
    ORDER BY r.id DESC LIMIT 1
), 0)
FROM delivery_history AS h
LEFT JOIN delivery_attempts AS a
    ON a.ip = h.ip AND a.revision = h.revision AND a.destination = h.destination
JOIN decisions AS d ON d.ip = h.ip AND d.revision = h.revision
WHERE h.destination = ? AND h.status IN ('retrying', 'exhausted')
GROUP BY h.ip, h.revision
`, name)
	if err != nil {
		return err
	}

	var updates []attemptStatusUpdate
	for rows.Next() {
		var ip string
		var revision, completed int64
		if err := rows.Scan(&ip, &revision, &completed); err != nil {
			_ = rows.Close()
			return err
		}
		updates = append(updates, attemptStatusUpdate{
			ip:       ip,
			revision: revision,
			status:   actions.StatusAfterFailure(completed, limit),
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, update := range updates {
		if _, err := tx.ExecContext(ctx, `
UPDATE delivery_history
SET status = ?
WHERE ip = ? AND revision = ? AND destination = ?
`, update.status, update.ip, update.revision, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// applyAttemptLimit atomically persists the retry status chosen by the application policy.
func applyAttemptLimit(ctx context.Context, tx *sql.Tx, name string, limit int, ip string, revision int64) error {
	var completed int64
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(number), 0) - COALESCE((
    SELECT previous_attempts FROM delivery_retries
    WHERE ip = ? AND revision = ? AND destination = ?
    ORDER BY id DESC LIMIT 1
), 0)
FROM delivery_attempts
WHERE ip = ? AND revision = ? AND destination = ?
`, ip, revision, name, ip, revision, name).Scan(&completed); err != nil {
		return err
	}

	_, err := tx.ExecContext(ctx, `
UPDATE delivery_history SET status = ?
WHERE ip = ? AND revision = ? AND destination = ? AND status = ?
`, actions.StatusAfterFailure(completed, limit), ip, revision, name, model.DeliveryRetrying)
	return err
}
