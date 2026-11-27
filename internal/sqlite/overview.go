package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

var _ overview.Store = (*Store)(nil)

// ListRevisions pages over immutable decision changes, newest first.
func (s *Store) ListRevisions(ctx context.Context, bounds overview.Query, ip string, state model.DecisionState) (overview.RevisionPage, error) {
	result := overview.RevisionPage{Items: []overview.Revision{}, Page: bounds.Page}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	result.ThroughSequence = bounds.ThroughSequence
	if result.ThroughSequence == 0 {
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence), 0) FROM decision_revisions").Scan(&result.ThroughSequence); err != nil {
			return result, err
		}
	}

	rows, err := tx.QueryContext(ctx, `
SELECT d.id, r.ip, r.revision, r.state, r.expires, r.changed_at, r.sources_json, r.cause
FROM decision_revisions AS r
JOIN decisions AS d ON d.ip = r.ip
WHERE r.sequence <= ? AND (? = '' OR r.ip = ?) AND (? = '' OR r.state = ?)
ORDER BY r.sequence DESC
LIMIT ? OFFSET ?
`, result.ThroughSequence, ip, ip, state, state, bounds.Limit+1, bounds.Offset)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item overview.Revision
		var expires, changed int64
		var sources string
		if err := rows.Scan(&item.DecisionID, &item.IPAddress, &item.Revision, &item.State, &expires, &changed, &sources, &item.Cause); err != nil {
			_ = rows.Close()
			return result, err
		}
		if len(result.Items) == bounds.Limit {
			result.NextPage = bounds.Page + 1
			break
		}
		item.ExpiresAt = time.UnixMilli(expires).UTC()
		item.ChangedAt = time.UnixMilli(changed).UTC()
		if err := json.Unmarshal([]byte(sources), &item.Sources); err != nil {
			_ = rows.Close()
			return result, err
		}
		if item.Sources == nil {
			item.Sources = []model.Source{}
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

// ListDeliveries pages over the latest revision for each decision/destination.
// History survives after a release even when a destination was fully acknowledged.
func (s *Store) ListDeliveries(ctx context.Context, bounds overview.Query, status model.DeliveryStatus, destination string) (overview.DeliveryPage, error) {
	result := overview.DeliveryPage{Items: []overview.Delivery{}, Page: bounds.Page}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
SELECT d.id, h.ip, h.revision, d.state, h.destination, h.status,
       CASE WHEN h.status = 'delivered' THEN h.revision ELSE COALESCE(q.acknowledged, 0) END,
       (SELECT COUNT(*) FROM delivery_attempts a
        WHERE a.ip = h.ip AND a.revision = h.revision AND a.destination = h.destination),
       r.changed_at,
       (SELECT MAX(a.completed_at) FROM delivery_attempts a
        WHERE a.ip = h.ip AND a.revision = h.revision AND a.destination = h.destination),
       CASE WHEN h.status = 'retrying' THEN MAX(COALESCE(q.retry_at, 0), COALESCE(b.retry_at, 0)) END,
       (SELECT SUBSTR(a.error, 1, 512) FROM delivery_attempts a
        WHERE a.ip = h.ip AND a.revision = h.revision AND a.destination = h.destination
        ORDER BY a.number DESC LIMIT 1)
FROM delivery_history AS h
JOIN decisions AS d ON d.ip = h.ip AND d.revision = h.revision
LEFT JOIN decision_revisions AS r ON r.ip = h.ip AND r.revision = h.revision
LEFT JOIN deliveries AS q ON q.ip = h.ip AND q.destination = h.destination
LEFT JOIN destination_backoff AS b ON b.destination = h.destination
WHERE (? = '' OR h.status = ?) AND (? = '' OR h.destination = ?)
ORDER BY COALESCE(r.changed_at, 0) DESC, h.ip, h.destination
LIMIT ? OFFSET ?
`, status, status, destination, destination, bounds.Limit+1, bounds.Offset)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item overview.Delivery
		var changed, last, next sql.NullInt64
		var diagnostic sql.NullString
		if err := rows.Scan(&item.DecisionID, &item.IPAddress, &item.Revision, &item.DesiredState, &item.Destination, &item.Status, &item.AcknowledgedRevision, &item.AttemptCount, &changed, &last, &next, &diagnostic); err != nil {
			_ = rows.Close()
			return result, err
		}
		if len(result.Items) == bounds.Limit {
			result.NextPage = bounds.Page + 1
			break
		}
		item.ChangedAt = optionalTime(changed)
		item.LastAttemptAt = optionalTime(last)
		if next.Valid && next.Int64 > 0 {
			item.NextAttemptAt = optionalTime(next)
		}
		if diagnostic.Valid {
			item.LastError = diagnostic.String
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	return result, tx.Commit()
}
