package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/workers"
)

// WorkerStats returns a read-only summary of active work and historical last activity.
func (s *Store) WorkerStats(ctx context.Context, now time.Time) (workers.QueueStats, error) {
	var stats workers.QueueStats
	var last sql.NullInt64

	err := s.db.QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(CASE WHEN h.status = 'pending' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN h.status = 'retrying' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN h.status = 'exhausted' THEN 1 ELSE 0 END), 0)
FROM delivery_history AS h
JOIN decisions AS d ON d.ip = h.ip AND d.revision = h.revision
`).Scan(&stats.PendingDeliveries, &stats.RetryingDeliveries, &stats.ExhaustedDeliveries)
	if err != nil {
		return workers.QueueStats{}, err
	}

	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT ip) FROM ban_sources WHERE expires > ?
`, now.UnixMilli()).Scan(&stats.ActiveBans); err != nil {
		return workers.QueueStats{}, err
	}

	if err := s.db.QueryRowContext(ctx, `
SELECT MAX(completed_at) FROM delivery_attempts
`).Scan(&last); err != nil {
		return workers.QueueStats{}, err
	}
	if last.Valid {
		completed := time.UnixMilli(last.Int64).UTC()
		stats.LastAttemptAt = &completed
	}

	return stats, nil
}
