package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// readDecision reads one persisted decision within the caller's transaction.
func readDecision(ctx context.Context, tx *sql.Tx, id string) (model.Decision, error) {
	var decision model.Decision
	var expires int64
	err := tx.QueryRowContext(
		ctx,
		`
SELECT
    id,
    revision,
    ip,
    state,
    expires
FROM decisions
WHERE id = ?
`,
		id,
	).Scan(
		&decision.ID,
		&decision.Revision,
		&decision.IP,
		&decision.State,
		&expires,
	)
	if err != nil {
		return model.Decision{}, err
	}
	decision.ExpiresAt = time.UnixMilli(expires).UTC()
	return decision, nil
}

// readDeliveries reads acknowledgements for one address in destination order.
func readDeliveries(ctx context.Context, tx *sql.Tx, ip string) ([]model.Acknowledgement, error) {
	rows, err := tx.QueryContext(
		ctx,
		`
SELECT destination, acknowledged
FROM deliveries
WHERE ip = ?
ORDER BY destination
`,
		ip,
	)
	if err != nil {
		return nil, err
	}

	deliveries := []model.Acknowledgement{}
	for rows.Next() {
		var ack model.Acknowledgement
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
func readBanSources(ctx context.Context, tx *sql.Tx, ip string, now time.Time) ([]model.Source, error) {
	rows, err := tx.QueryContext(
		ctx,
		`
SELECT kind, expires, reason
FROM ban_sources
WHERE ip = ?
    AND expires > ?
ORDER BY kind
`,
		ip,
		now.UnixMilli(),
	)
	if err != nil {
		return nil, err
	}

	sources := []model.Source{}
	for rows.Next() {
		var source model.Source
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
