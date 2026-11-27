package sqlite

import (
	"context"
	"fmt"
	"time"
)

// Prune removes old observations independently of delivery activity.
func (s *Store) Prune(ctx context.Context, observationCutoff, incidentCutoff time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM incidents WHERE observed_at <= ?`, incidentCutoff.UnixMilli()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM notification_deliveries
WHERE state <> 'pending'
    AND completed_at <= ?
`, incidentCutoff.UnixMilli()); err != nil {
		return err
	}
	_, err = tx.ExecContext(
		ctx,
		`
DELETE FROM event_observations
WHERE received <= ?
`,
		observationCutoff.UnixMilli(),
	)
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
