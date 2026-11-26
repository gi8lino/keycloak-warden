package sqlite

import (
	"context"
	"fmt"
	"time"
)

// Prune removes old observations independently of delivery activity.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM ban_observations WHERE observed_at <= ?`, cutoff.UnixMilli()); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
DELETE FROM failures
WHERE received <= ?
`, cutoff.UnixMilli())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Optimize refreshes SQLite query-planner statistics without rebuilding the database.
func (s *Store) Optimize(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA optimize")
	if err != nil {
		return fmt.Errorf("optimize sqlite database: %w", err)
	}
	return nil
}
