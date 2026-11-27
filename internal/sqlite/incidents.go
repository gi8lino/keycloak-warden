package sqlite

import (
	"context"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// RecordIncident persists a threshold hit and its notification jobs atomically.
func (t *transaction) RecordIncident(ctx context.Context, item model.Incident, destinations []string) (int64, error) {
	var banUntil, effectiveBanUntil any
	if item.BanUntil != nil {
		banUntil = item.BanUntil.UnixMilli()
	}
	if item.EffectiveBanUntil != nil {
		effectiveBanUntil = item.EffectiveBanUntil.UnixMilli()
	}
	result, err := t.tx.ExecContext(
		ctx,
		`
INSERT INTO incidents (
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
)
VALUES (
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?
)
`,
		item.Rule,
		item.Source,
		item.EventID,
		item.EventKind,
		item.EventType,
		item.RealmID,
		item.ActorRealmID,
		item.UserID,
		item.ClientID,
		item.IP,
		item.Error,
		item.OperationType,
		item.ResourceType,
		item.ResourcePath,
		item.EventAt.UnixMilli(),
		item.At.UnixMilli(),
		item.Count,
		item.Threshold,
		banUntil,
		item.ObserveOnly,
		item.GroupBy,
		item.GroupKey,
		item.IdentityRealm,
		item.Distinct,
		item.Window,
		effectiveBanUntil,
		item.DecisionID,
		item.DecisionRevision,
	)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	item.ID = id
	if err := t.enqueueNotifications(ctx, item, destinations); err != nil {
		return 0, err
	}
	return id, nil
}
