package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// readDecision reads one persisted decision within the caller's transaction.
func readDecision(ctx context.Context, tx *sql.Tx, id string) (decisions.Decision, error) {
	var decision decisions.Decision
	var expires int64
	var active bool
	err := tx.QueryRowContext(ctx, `
SELECT id, revision, ip, active, expires
FROM decisions
WHERE id = ?
`, id).Scan(
		&decision.ID,
		&decision.Revision,
		&decision.IP,
		&active,
		&expires,
	)
	if err != nil {
		return decisions.Decision{}, err
	}
	decision.State = stateFromActive(active)
	decision.ExpiresAt = time.UnixMilli(expires).UTC()
	return decision, nil
}

// readDeliveries reads acknowledgements for one address in destination order.
func readDeliveries(ctx context.Context, tx *sql.Tx, ip string) ([]decisions.Acknowledgement, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT destination, acknowledged
FROM deliveries
WHERE ip = ?
ORDER BY destination
`, ip)
	if err != nil {
		return nil, err
	}

	deliveries := []decisions.Acknowledgement{}
	for rows.Next() {
		var ack decisions.Acknowledgement
		if err := rows.Scan(&ack.Destination, &ack.Revision); err != nil {
			_ = rows.Close()
			return nil, err
		}
		deliveries = append(deliveries, ack)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return deliveries, nil
}

// readBanSources reads unexpired automatic and manual sources in kind order.
func readBanSources(ctx context.Context, tx *sql.Tx, ip string, now time.Time) ([]bans.Source, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT kind, expires, reason
FROM ban_sources
WHERE ip = ? AND expires > ?
ORDER BY kind
`, ip, now.UnixMilli())
	if err != nil {
		return nil, err
	}

	sources := []bans.Source{}
	for rows.Next() {
		var source bans.Source
		var until int64
		if err := rows.Scan(&source.Kind, &until, &source.Reason); err != nil {
			_ = rows.Close()
			return nil, err
		}
		source.ExpiresAt = time.UnixMilli(until).UTC()
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return sources, nil
}
