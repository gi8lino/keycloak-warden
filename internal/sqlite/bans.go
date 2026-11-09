package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// BanManual creates or extends one manual source and queues the resulting effective state.
func (s *Store) BanManual(
	ctx context.Context,
	ip string,
	until time.Time,
	reason string,
	now time.Time,
) (bans.Ban, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return bans.Ban{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := ensureDecision(ctx, tx, ip); err != nil {
		return bans.Ban{}, err
	}
	if err := setSource(ctx, tx, ip, bans.SourceManual, until, reason); err != nil {
		return bans.Ban{}, err
	}
	decision, err := reconcileDecision(ctx, tx, ip, now, s.targets, nil)
	if err != nil {
		return bans.Ban{}, err
	}
	view, err := readBan(ctx, tx, decision.ID, now)
	if err != nil {
		return bans.Ban{}, err
	}
	return view, s.commitDecision(tx)
}

// UnbanAll removes every active source and resets the failed-login count atomically.
func (s *Store) UnbanAll(ctx context.Context, id string, now time.Time) (bans.Ban, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return bans.Ban{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var ip string
	err = tx.QueryRowContext(ctx, `
SELECT ip
FROM decisions
WHERE id = ? AND active = 1 AND expires > ?
`, id, now.UnixMilli()).Scan(&ip)
	if errors.Is(err, sql.ErrNoRows) {
		return bans.Ban{}, bans.ErrNotFound
	}
	if err != nil {
		return bans.Ban{}, err
	}

	// Remove expired rows as well so the next maintenance pass cannot
	// reconcile the same IP again and issue another release revision.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM ban_sources
WHERE ip = ?
`, ip); err != nil {
		return bans.Ban{}, err
	}

	// Keep observed event IDs for replay deduplication, but ignore prior
	// observations when counting future failures. The generation is incremented
	// in the same transaction as the unblock decision and delivery revision.
	if _, err := tx.ExecContext(ctx, `
UPDATE decisions
SET failure_generation = failure_generation + 1
WHERE ip = ?
`, ip); err != nil {
		return bans.Ban{}, err
	}

	zero := 0
	decision, err := reconcileDecision(ctx, tx, ip, now, s.targets, &zero)
	if err != nil {
		return bans.Ban{}, err
	}
	view, err := readBan(ctx, tx, decision.ID, now)
	if err != nil {
		return bans.Ban{}, err
	}
	return view, s.commitDecision(tx)
}

// ListBans returns all currently active effective bans, with source and delivery details.
func (s *Store) ListBans(ctx context.Context, now time.Time) ([]bans.Ban, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	list, err := listBans(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	return list, tx.Commit()
}

// listBans loads active decisions, sources and acknowledgements with three queries.
// All three queries share the caller's read-only transaction and snapshot.
func listBans(ctx context.Context, tx *sql.Tx, now time.Time) ([]bans.Ban, error) {
	list, byIP, err := readActiveBans(ctx, tx, now)
	if err != nil || len(list) == 0 {
		return list, err
	}

	if err := appendActiveSources(ctx, tx, list, byIP, now); err != nil {
		return nil, err
	}
	if err := appendActiveDeliveries(ctx, tx, list, byIP, now); err != nil {
		return nil, err
	}
	return list, nil
}

// readActiveBans selects active decisions in IP order and indexes their positions.
func readActiveBans(ctx context.Context, tx *sql.Tx, now time.Time) ([]bans.Ban, map[string]int, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, revision, ip, active, expires, failures
FROM decisions
WHERE active = 1 AND expires > ?
ORDER BY ip
`, now.UnixMilli())
	if err != nil {
		return nil, nil, err
	}

	list := []bans.Ban{}
	byIP := make(map[string]int)
	for rows.Next() {
		view := bans.Ban{
			Sources:    []bans.Source{},
			Deliveries: []decisions.Acknowledgement{},
		}
		var expires int64
		if err := rows.Scan(
			&view.Decision.ID, &view.Decision.Revision, &view.Decision.IP,
			&view.Decision.Active, &expires, &view.Decision.Failures,
		); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		view.Decision.ExpiresAt = time.UnixMilli(expires).UTC()
		byIP[view.Decision.IP] = len(list)
		list = append(list, view)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	return list, byIP, nil
}

// appendActiveSources attaches unexpired sources to the selected active decisions.
func appendActiveSources(ctx context.Context, tx *sql.Tx, list []bans.Ban, byIP map[string]int, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `
SELECT s.ip, s.kind, s.expires, s.reason
FROM ban_sources AS s
JOIN decisions AS d ON d.ip = s.ip
WHERE d.active = 1 AND d.expires > ? AND s.expires > ?
ORDER BY s.ip, s.kind
`, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return err
	}

	for rows.Next() {
		var ip string
		var source bans.Source
		var expires int64
		if err := rows.Scan(&ip, &source.Kind, &expires, &source.Reason); err != nil {
			_ = rows.Close()
			return err
		}
		source.ExpiresAt = time.UnixMilli(expires).UTC()
		list[byIP[ip]].Sources = append(list[byIP[ip]].Sources, source)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}

// appendActiveDeliveries attaches destination acknowledgements in destination order.
func appendActiveDeliveries(ctx context.Context, tx *sql.Tx, list []bans.Ban, byIP map[string]int, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `
SELECT q.ip, q.destination, q.acknowledged
FROM deliveries AS q
JOIN decisions AS d ON d.ip = q.ip
WHERE d.active = 1 AND d.expires > ?
ORDER BY q.ip, q.destination
`, now.UnixMilli())
	if err != nil {
		return err
	}

	for rows.Next() {
		var ip string
		var ack decisions.Acknowledgement
		if err := rows.Scan(&ip, &ack.Destination, &ack.Revision); err != nil {
			_ = rows.Close()
			return err
		}
		list[byIP[ip]].Deliveries = append(list[byIP[ip]].Deliveries, ack)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}

// GetBan returns the persisted decision and all currently active sources.
func (s *Store) GetBan(ctx context.Context, id string, now time.Time) (bans.Ban, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return bans.Ban{}, err
	}
	defer func() { _ = tx.Rollback() }()
	view, err := readBan(ctx, tx, id, now)
	if err != nil {
		return bans.Ban{}, err
	}
	return view, tx.Commit()
}

// readBan loads a decision, its active sources and deliveries from one transaction.
func readBan(ctx context.Context, tx *sql.Tx, id string, now time.Time) (bans.Ban, error) {
	decision, err := readDecision(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return bans.Ban{}, bans.ErrNotFound
	}
	if err != nil {
		return bans.Ban{}, err
	}

	sources, err := readBanSources(ctx, tx, decision.IP, now)
	if err != nil {
		return bans.Ban{}, err
	}

	deliveries, err := readDeliveries(ctx, tx, decision.IP)
	if err != nil {
		return bans.Ban{}, err
	}

	return bans.Ban{Decision: decision, Sources: sources, Deliveries: deliveries}, nil
}
