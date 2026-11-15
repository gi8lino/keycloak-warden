package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"uuid"
)

// EnsureDecision creates a stable UUIDv7 identity before attaching ban sources.
func (t *transaction) EnsureDecision(ctx context.Context, ip string) error {
	_, err := t.tx.ExecContext(ctx, `
INSERT INTO decisions (ip, id, revision, active, expires)
VALUES (?, ?, 0, 0, 0)
ON CONFLICT (ip) DO NOTHING
`, ip, uuid.NewV7().String())
	return err
}

// Decision reads the materialized current state for a given IP.
func (t *transaction) Decision(ctx context.Context, ip string) (decisions.Decision, error) {
	return readDecisionByIP(ctx, t.tx, ip)
}

// SaveDecision persists the application-calculated decision and reconciles its
// destination delivery rows and history within the existing SQL transaction.
// A change updates the decision revision and schedules delivery; an unchanged
// decision can still synchronize configured destination ownership. It neither
// begins nor commits a transaction.
func (t *transaction) SaveDecision(ctx context.Context, previous, decision decisions.Decision, changed bool, targets []string) error {
	if changed {
		t.changed = true
		if _, err := t.tx.ExecContext(ctx, `
UPDATE decisions
SET revision = ?, active = ?, expires = ?
WHERE ip = ?
`, decision.Revision, decision.State == decisionstate.StateBanned,
			decision.ExpiresAt.UnixMilli(), decision.IP); err != nil {
			return err
		}
	}

	// A fully acknowledged release no longer owns a destination, whereas an
	// unacknowledged release must remain queued until accepted externally.
	if _, err := t.tx.ExecContext(ctx, `
DELETE FROM deliveries
WHERE ip = ? AND acknowledged = ? AND ? = 1
`, decision.IP, previous.Revision, previous.State == decisionstate.StateUnbanned); err != nil {
		return err
	}

	for _, name := range targets {
		if _, err := t.tx.ExecContext(ctx, `
INSERT INTO deliveries (ip, destination)
VALUES (?, ?)
ON CONFLICT (ip, destination) DO NOTHING
`, decision.IP, name); err != nil {
			return err
		}
	}
	return syncDeliveryHistory(ctx, t.tx, decision)
}

// readDecisionByIP loads the current materialized decision within the transaction.
func readDecisionByIP(ctx context.Context, tx *sql.Tx, ip string) (decisions.Decision, error) {
	var result decisions.Decision
	var active bool
	var expires int64
	err := tx.QueryRowContext(ctx, `
SELECT id, revision, active, expires FROM decisions WHERE ip = ?
`, ip).Scan(&result.ID, &result.Revision, &active, &expires)
	if err != nil {
		return decisions.Decision{}, err
	}
	result.IP = ip
	result.State = stateFromActive(active)
	result.ExpiresAt = time.UnixMilli(expires).UTC()
	return result, nil
}

// DecisionByID reads the current decision identified by its stable ID.
func (t *transaction) DecisionByID(ctx context.Context, id string) (decisions.Decision, error) {
	decision, err := readDecision(ctx, t.tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return decisions.Decision{}, bans.ErrNotFound
	}
	return decision, err
}
