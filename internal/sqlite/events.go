package sqlite

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

// RecordEvent persists a normalized envelope only once per producer and identifier.
func (t *transaction) RecordEvent(ctx context.Context, event events.Envelope, now time.Time, banEligible bool) (inserted bool, err error) {
	result, err := t.tx.ExecContext(
		ctx,
		`
INSERT INTO event_observations (
    source,
    event_id,
    ip,
    received,
    generation,
    event_kind,
    event_type,
    realm_id,
    identity_realm,
    user_id,
    operation_type,
    resource_type,
    event_error,
    ban_eligible
)
VALUES (
    ?,
    ?,
    ?,
    ?,
    COALESCE((
        SELECT failure_generation
        FROM decisions
        WHERE ip = ?
    ), 0),
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
ON CONFLICT DO NOTHING
`,
		event.Source,
		event.ID,
		event.Address(),
		now.UnixMilli(),
		event.Address(),
		event.Kind,
		event.EventType(),
		event.RealmID(),
		event.IdentityRealm(),
		event.UserID(),
		event.OperationType(),
		event.ResourceType(),
		event.ErrorCode(),
		banEligible,
	)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

// AdvanceBanGeneration advances the observation generation while retaining producer IDs.
func (t *transaction) AdvanceBanGeneration(ctx context.Context, ip string) error {
	_, err := t.tx.ExecContext(
		ctx,
		`
UPDATE decisions
SET failure_generation = failure_generation + 1
WHERE ip = ?
`,
		ip,
	)
	if err == nil {
		t.changed = true
	}
	return err
}
