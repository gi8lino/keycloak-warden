package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
)

// ReconcileAttemptLimit updates current undelivered revisions for one destination.
// It runs at startup, does not persist the configured limit, and preserves attempt history.
func (s *Store) ReconcileAttemptLimit(ctx context.Context, name string, limit int) error {
	if !slices.Contains(s.targets, name) {
		return fmt.Errorf("destination %q is not configured", name)
	}
	if limit < 1 {
		return errors.New("max-attempts must be at least 1")
	}

	_, err := s.db.ExecContext(ctx, `
UPDATE delivery_history AS h
SET status = CASE WHEN (
    SELECT MAX(number) FROM delivery_attempts a
    WHERE a.ip = h.ip AND a.revision = h.revision AND a.destination = h.destination
) >= ? THEN 'exhausted' ELSE 'retrying' END
WHERE h.destination = ? AND h.status IN ('retrying', 'exhausted')
  AND h.revision = (SELECT revision FROM decisions WHERE ip = h.ip)
`, limit, name)
	return err
}

// applyAttemptLimit marks the attempted revision terminal when its persisted count reaches the limit.
func applyAttemptLimit(ctx context.Context, tx *sql.Tx, name string, limit int, ip string, revision int64) error {
	_, err := tx.ExecContext(ctx, `
UPDATE delivery_history SET status = 'exhausted'
WHERE ip = ? AND revision = ? AND destination = ? AND status = 'retrying'
  AND EXISTS (
      SELECT 1 FROM delivery_attempts
      WHERE ip = ? AND revision = ? AND destination = ? AND number >= ?
  )
`, ip, revision, name, ip, revision, name, limit)
	return err
}
