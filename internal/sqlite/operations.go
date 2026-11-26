package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
)

// DestinationHealth aggregates all current revisions, not just one overview page.
func (s *Store) DestinationHealth(ctx context.Context) ([]overview.DestinationHealth, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT h.destination, SUM(h.status='pending'), SUM(h.status='retrying'), SUM(h.status='exhausted'),
 SUM(d.state='unbanned' AND h.status IN ('retrying','exhausted')),
 SUM(d.state='unbanned' AND h.status='exhausted'), SUM(h.status='delivered')
FROM delivery_history h JOIN decisions d ON d.ip=h.ip AND d.revision=h.revision
GROUP BY h.destination ORDER BY 6 DESC,5 DESC,4 DESC,3 DESC,h.destination`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	result := []overview.DestinationHealth{}
	for rows.Next() {
		var item overview.DestinationHealth
		if err := rows.Scan(&item.Destination, &item.Pending, &item.Retrying, &item.Exhausted, &item.FailedUnbans, &item.ExhaustedUnbans, &item.Delivered); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// Timeline combines audit tables in a consistent read transaction and orders by recorded time.
func (s *Store) Timeline(ctx context.Context, id string, bounds overview.Query) (overview.TimelinePage, error) {
	result := overview.TimelinePage{Items: []overview.TimelineEvent{}, Page: bounds.Page}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	result.DecisionID = id
	if err := tx.QueryRowContext(ctx, `SELECT ip FROM decisions WHERE id = ?`, id).Scan(&result.IP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, overview.ErrTimelineNotFound
		}
		return result, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT at, kind, action, source_kind, state, revision, destination, detail, actor, expires, attempt
FROM (
    SELECT changed_at AS at, 'source' AS kind, action, kind AS source_kind, '' AS state,
           0 AS revision, '' AS destination, SUBSTR(reason, 1, 512) AS detail,
           '' AS actor, expires, 0 AS attempt, id AS seq
    FROM source_changes WHERE ip = ?
    UNION ALL
    SELECT changed_at, 'decision', cause, '', state, revision, '', '', '', expires, 0, sequence
    FROM decision_revisions WHERE ip = ?
    UNION ALL
    SELECT completed_at, 'attempt', CASE WHEN error IS NULL THEN 'succeeded' ELSE 'failed' END,
           '', '', revision, destination, COALESCE(SUBSTR(error, 1, 512), ''), '', NULL, number, number
    FROM delivery_attempts WHERE ip = ?
    UNION ALL
    SELECT requested_at, 'retry', 'requested', '', '', revision, destination, '', actor, NULL, 0, id
    FROM delivery_retries WHERE ip = ?
)
ORDER BY at DESC, kind, revision DESC, destination, seq DESC
LIMIT ? OFFSET ?
`, result.IP, result.IP, result.IP, result.IP, bounds.Limit+1, bounds.Offset)
	if err != nil {
		return result, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var item overview.TimelineEvent
		var at int64
		var expires sql.NullInt64
		if err := rows.Scan(&at, &item.Kind, &item.Action, &item.SourceKind, &item.State, &item.Revision, &item.Destination, &item.Detail, &item.Actor, &expires, &item.Attempt); err != nil {
			return result, err
		}
		if len(result.Items) == bounds.Limit {
			result.NextPage = bounds.Page + 1
			break
		}
		item.At = time.UnixMilli(at).UTC()
		item.ExpiresAt = optionalTime(expires)
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

// Observations pages through hypothetical threshold hits without consulting enforcement state.
func (s *Store) Observations(ctx context.Context, bounds overview.Query) (overview.ObservationPage, error) {
	result := overview.ObservationPage{Items: []ingestion.Observation{}, Page: bounds.Page}
	rows, err := s.db.QueryContext(ctx, `SELECT source,event_id,ip,observed_at,expires,failures,threshold FROM ban_observations ORDER BY id DESC LIMIT ? OFFSET ?`, bounds.Limit+1, bounds.Offset)
	if err != nil {
		return result, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var item ingestion.Observation
		var at, expires int64
		if err := rows.Scan(&item.Source, &item.EventID, &item.IP, &at, &expires, &item.Failures, &item.Threshold); err != nil {
			return result, err
		}
		if len(result.Items) == bounds.Limit {
			result.NextPage = bounds.Page + 1
			break
		}
		item.At = time.UnixMilli(at).UTC()
		item.ExpiresAt = time.UnixMilli(expires).UTC()
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}
