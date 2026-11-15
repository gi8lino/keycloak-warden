package sqlite

import (
	"context"
	"fmt"
	"time"
)

// Prune removes old observations independently of delivery activity.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM failures
WHERE received <= ?
`, cutoff.UnixMilli())
	return err
}

// Optimize refreshes SQLite query-planner statistics without rebuilding the database.
func (s *Store) Optimize(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA optimize")
	if err != nil {
		return fmt.Errorf("optimize sqlite database: %w", err)
	}
	return nil
}
