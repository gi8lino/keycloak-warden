package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// RetryDelivery requeues an exhausted current delivery without changing its revision or attempt history.
func (s *Store) RetryDelivery(ctx context.Context, request model.RetryRequest, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var ip string
	var completed int64
	err = tx.QueryRowContext(ctx, `
SELECT d.ip, COALESCE((SELECT MAX(a.number) FROM delivery_attempts a WHERE a.ip=d.ip AND a.revision=d.revision AND a.destination=h.destination),0)
FROM decisions d JOIN delivery_history h ON h.ip=d.ip AND h.revision=d.revision
JOIN deliveries q ON q.ip=d.ip AND q.destination=h.destination
WHERE d.id=? AND d.revision=? AND h.destination=? AND h.status='exhausted'
 AND q.acknowledged<d.revision AND (d.state='unbanned' OR d.expires>?)`, request.DecisionID, request.Revision, request.Destination, now.UnixMilli()).Scan(&ip, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return actions.ErrRetryConflict
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO delivery_retries(ip,revision,destination,requested_at,actor,previous_attempts) VALUES(?,?,?,?,?,?)`, ip, request.Revision, request.Destination, now.UnixMilli(), request.Actor, completed); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE delivery_history SET status='pending' WHERE ip=? AND revision=? AND destination=?`, ip, request.Revision, request.Destination); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET retry_at=0 WHERE ip=? AND destination=?`, ip, request.Destination); err != nil {
		return err
	}
	// Preserve the shared destination backoff: a retry must not defeat rate limiting for unrelated work.
	return s.commitDecision(tx)
}
