package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

// observationTx implements ingestion's atomic storage operations.
type observationTx struct {
	// tx holds the transaction used by the observation operation.
	tx *sql.Tx
	// targets lists the configured destinations for new decisions.
	targets []string
	// changed indicates source updates that should wake the delivery worker after commit.
	changed bool
}

// RecordFailure persists a new occurrence only once per producer and identifier.
func (o *observationTx) RecordFailure(ctx context.Context, event events.Event, now time.Time) (inserted bool, err error) {
	result, err := o.tx.ExecContext(ctx, `
INSERT INTO failures (source, event_id, ip, received, generation)
VALUES (?, ?, ?, ?, COALESCE((
    SELECT failure_generation
    FROM decisions
    WHERE ip = ?
), 0))
ON CONFLICT DO NOTHING
`, event.Source, event.ID, event.IP.String(), now.UnixMilli(), event.IP.String())
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

// CountFailures counts observations visible within the current transaction and window.
func (o *observationTx) CountFailures(ctx context.Context, ip string, since time.Time) (count int, err error) {
	err = o.tx.QueryRowContext(ctx, `
SELECT count(*)
FROM failures
WHERE ip = ?
    AND received > ?
    AND generation = COALESCE((
        SELECT failure_generation
        FROM decisions
        WHERE ip = ?
    ), 0)
`, ip, since.UnixMilli(), ip).Scan(&count)
	return count, err
}

// Block extends the automatic reason while preserving any independent manual ban.
func (o *observationTx) Block(
	ctx context.Context,
	ip string,
	until, now time.Time,
) (*decisions.Decision, error) {
	if err := ensureDecision(ctx, o.tx, ip); err != nil {
		return nil, err
	}
	if err := setSource(ctx, o.tx, ip, bans.SourceAutomatic, until, ""); err != nil {
		return nil, err
	}
	decision, revised, err := reconcileDecision(ctx, o.tx, ip, now, o.targets)
	if err != nil {
		return nil, err
	}
	// A source may have changed even if an existing manual ban keeps the
	// effective decision unchanged. The worker still needs an expiry wakeup.
	o.changed = true
	if !revised {
		return nil, nil
	}
	return &decision, nil
}
