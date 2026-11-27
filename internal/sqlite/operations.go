package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// DestinationHealth aggregates all current revisions, not just one overview page.
func (s *Store) DestinationHealth(ctx context.Context) ([]model.DestinationHealth, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
    h.destination,
    SUM(h.status = 'pending'),
    SUM(h.status = 'retrying'),
    SUM(h.status = 'exhausted'),
    SUM(d.state = 'unbanned' AND h.status IN ('retrying', 'exhausted')),
    SUM(d.state = 'unbanned' AND h.status = 'exhausted'),
    SUM(h.status = 'delivered')
FROM delivery_history h
JOIN decisions d ON d.ip = h.ip
    AND d.revision = h.revision
GROUP BY h.destination
ORDER BY 6 DESC, 5 DESC, 4 DESC, 3 DESC, h.destination
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	result := []model.DestinationHealth{}
	for rows.Next() {
		var item model.DestinationHealth
		if err := rows.Scan(
			&item.Destination,
			&item.Pending,
			&item.Retrying,
			&item.Exhausted,
			&item.FailedUnbans,
			&item.ExhaustedUnbans,
			&item.Delivered,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// Timeline combines audit tables in a consistent read transaction and orders by recorded time.
func (s *Store) Timeline(ctx context.Context, id string, bounds overview.Query) (model.TimelinePage, error) {
	result := model.TimelinePage{Items: []model.TimelineEvent{}, Page: bounds.Page}
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
	rows, err := tx.QueryContext(
		ctx,
		`
SELECT
    at,
    kind,
    action,
    source_kind,
    state,
    revision,
    destination,
    detail,
    actor,
    expires,
    attempt
FROM (
    SELECT
        changed_at AS at,
        'source' AS kind,
        action,
        kind AS source_kind,
        '' AS state,
        0 AS revision,
        '' AS destination,
        SUBSTR(reason, 1, 512) AS detail,
        '' AS actor,
        expires,
        0 AS attempt,
        id AS seq
    FROM source_changes
    WHERE ip = ?

    UNION ALL

    SELECT
        changed_at,
        'decision',
        cause,
        '',
        state,
        revision,
        '',
        '',
        '',
        expires,
        0,
        sequence
    FROM decision_revisions
    WHERE ip = ?

    UNION ALL

    SELECT
        completed_at,
        'attempt',
        CASE WHEN error IS NULL THEN 'succeeded' ELSE 'failed' END,
        '',
        '',
        revision,
        destination,
        COALESCE(SUBSTR(error, 1, 512), ''),
        '',
        NULL,
        number,
        number
    FROM delivery_attempts
    WHERE ip = ?

    UNION ALL

    SELECT
        requested_at,
        'retry',
        'requested',
        '',
        '',
        revision,
        destination,
        '',
        actor,
        NULL,
        0,
        id
    FROM delivery_retries
    WHERE ip = ?
)
ORDER BY at DESC, kind, revision DESC, destination, seq DESC
LIMIT ? OFFSET ?
`,
		result.IP,
		result.IP,
		result.IP,
		result.IP,
		bounds.Limit+1,
		bounds.Offset,
	)
	if err != nil {
		return result, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var item model.TimelineEvent
		var at int64
		var expires sql.NullInt64
		if err := rows.Scan(
			&at,
			&item.Kind,
			&item.Action,
			&item.SourceKind,
			&item.State,
			&item.Revision,
			&item.Destination,
			&item.Detail,
			&item.Actor,
			&expires,
			&item.Attempt,
		); err != nil {
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

// Incidents pages through named detection rule threshold hits.
func (s *Store) Incidents(ctx context.Context, query overview.IncidentQuery) (model.IncidentPage, error) {
	result := model.IncidentPage{Items: []model.Incident{}}
	rows, err := s.db.QueryContext(
		ctx,
		`
SELECT
    id,
    rule,
    source,
    event_id,
    event_kind,
    event_type,
    realm_id,
    actor_realm_id,
    user_id,
    client_id,
    ip,
    event_error,
    operation_type,
    resource_type,
    resource_path,
    event_at,
    observed_at,
    count,
    threshold,
    ban_until,
    observe_only,
    group_by,
    group_key,
    group_identity_realm,
    distinct_by,
    window,
    effective_ban_until,
    decision_id,
    decision_revision
FROM incidents
WHERE (? = 0 OR id < ?)
    AND (? = '' OR rule = ?)
    AND (? = '' OR event_kind = ?)
ORDER BY id DESC
LIMIT ?
`,
		query.BeforeID,
		query.BeforeID,
		query.Rule,
		query.Rule,
		query.Kind,
		query.Kind,
		overview.PageSize+1,
	)
	if err != nil {
		return result, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		if len(result.Items) == overview.PageSize {
			result.NextBeforeID = result.Items[len(result.Items)-1].ID
			break
		}
		var item model.Incident
		var eventAt, at int64
		var until, effectiveUntil sql.NullInt64
		if err := rows.Scan(
			&item.ID,
			&item.Rule,
			&item.Source,
			&item.EventID,
			&item.EventKind,
			&item.EventType,
			&item.RealmID,
			&item.ActorRealmID,
			&item.UserID,
			&item.ClientID,
			&item.IP,
			&item.Error,
			&item.OperationType,
			&item.ResourceType,
			&item.ResourcePath,
			&eventAt,
			&at,
			&item.Count,
			&item.Threshold,
			&until,
			&item.ObserveOnly,
			&item.GroupBy,
			&item.GroupKey,
			&item.IdentityRealm,
			&item.Distinct,
			&item.Window,
			&effectiveUntil,
			&item.DecisionID,
			&item.DecisionRevision,
		); err != nil {
			return result, err
		}
		item.EventAt = time.UnixMilli(eventAt).UTC()
		item.At = time.UnixMilli(at).UTC()
		item.BanUntil = optionalTime(until)
		item.EffectiveBanUntil = optionalTime(effectiveUntil)
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}
