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

// listBans reads active decisions and their sources in a consistent transaction.
func listBans(ctx context.Context, tx *sql.Tx, now time.Time) (list []bans.Ban, err error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id
FROM decisions
WHERE active = 1 AND expires > ?
ORDER BY ip
`, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	list = make([]bans.Ban, 0, len(ids))
	for _, id := range ids {
		view, err := readBan(ctx, tx, id, now)
		if err != nil {
			return nil, err
		}
		list = append(list, view)
	}
	return list, nil
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

// readBan loads one effective state and its reason and delivery records from a transaction.
func readBan(ctx context.Context, tx *sql.Tx, id string, now time.Time) (view bans.Ban, err error) {
	view = bans.Ban{Sources: []bans.Source{}, Deliveries: []decisions.Acknowledgement{}}
	var expires int64
	err = tx.QueryRowContext(ctx, `
SELECT id, revision, ip, active, expires, failures
FROM decisions
WHERE id = ?
`, id).Scan(
		&view.Decision.ID,
		&view.Decision.Revision,
		&view.Decision.IP,
		&view.Decision.Active,
		&expires,
		&view.Decision.Failures,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return bans.Ban{}, bans.ErrNotFound
	}
	if err != nil {
		return bans.Ban{}, err
	}
	view.Decision.ExpiresAt = time.UnixMilli(expires).UTC()

	rows, err := tx.QueryContext(ctx, `
SELECT kind, expires, reason
FROM ban_sources
WHERE ip = ? AND expires > ?
ORDER BY kind
`, view.Decision.IP, now.UnixMilli())
	if err != nil {
		return bans.Ban{}, err
	}
	for rows.Next() {
		var source bans.Source
		var until int64
		if err := rows.Scan(&source.Kind, &until, &source.Reason); err != nil {
			_ = rows.Close()
			return bans.Ban{}, err
		}
		source.ExpiresAt = time.UnixMilli(until).UTC()
		view.Sources = append(view.Sources, source)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return bans.Ban{}, err
	}
	if err := rows.Close(); err != nil {
		return bans.Ban{}, err
	}

	rows, err = tx.QueryContext(ctx, `
SELECT destination, acknowledged
FROM deliveries
WHERE ip = ?
ORDER BY destination
`, view.Decision.IP)
	if err != nil {
		return bans.Ban{}, err
	}
	for rows.Next() {
		var ack decisions.Acknowledgement
		if err := rows.Scan(&ack.Destination, &ack.Revision); err != nil {
			_ = rows.Close()
			return bans.Ban{}, err
		}
		view.Deliveries = append(view.Deliveries, ack)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return bans.Ban{}, err
	}
	return view, rows.Close()
}
