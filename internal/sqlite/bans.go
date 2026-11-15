package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// Store fulfills the application's atomic ban administration contract.
var _ bans.Store = (*Store)(nil)

// ListActive returns all currently active effective bans, with source and delivery details.
func (s *Store) ListActive(ctx context.Context, now time.Time) ([]bans.Record, error) {
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

// listBans reads active decisions, sources and acknowledgements in one consistent snapshot.
func listBans(ctx context.Context, tx *sql.Tx, now time.Time) ([]bans.Record, error) {
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
func readActiveBans(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
) (list []bans.Record, byIP map[string]int, err error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, revision, ip, state, expires
FROM decisions
WHERE state = ? AND expires > ?
ORDER BY ip
`, decisionstate.StateBanned, now.UnixMilli())
	if err != nil {
		return nil, nil, err
	}

	list = []bans.Record{}
	byIP = make(map[string]int)
	for rows.Next() {
		record := bans.Record{
			Sources:    []bans.Source{},
			Deliveries: []decisions.Acknowledgement{},
		}
		var expires int64
		if err := rows.Scan(
			&record.Decision.ID, &record.Decision.Revision, &record.Decision.IP,
			&record.Decision.State, &expires,
		); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		record.Decision.ExpiresAt = time.UnixMilli(expires).UTC()
		byIP[record.Decision.IP] = len(list)
		list = append(list, record)
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
func appendActiveSources(
	ctx context.Context,
	tx *sql.Tx,
	list []bans.Record,
	byIP map[string]int,
	now time.Time,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT s.ip, s.kind, s.expires, s.reason
FROM ban_sources AS s
JOIN decisions AS d ON d.ip = s.ip
WHERE d.state = ? AND d.expires > ? AND s.expires > ?
ORDER BY s.ip, s.kind
`, decisionstate.StateBanned, now.UnixMilli(), now.UnixMilli())
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
func appendActiveDeliveries(
	ctx context.Context,
	tx *sql.Tx,
	list []bans.Record,
	byIP map[string]int,
	now time.Time,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT q.ip, q.destination, q.acknowledged
FROM deliveries AS q
JOIN decisions AS d ON d.ip = q.ip
WHERE d.state = ? AND d.expires > ?
ORDER BY q.ip, q.destination
`, decisionstate.StateBanned, now.UnixMilli())
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

// GetDecision returns the persisted decision and all currently active sources.
func (s *Store) GetDecision(ctx context.Context, id string, now time.Time) (bans.Record, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return bans.Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := readBan(ctx, tx, id, now)
	if err != nil {
		return bans.Record{}, err
	}
	record.DeliveryHistory, err = readDeliveryHistory(ctx, tx, record.Decision.IP)
	if err != nil {
		return bans.Record{}, err
	}
	return record, tx.Commit()
}

// readBan loads a decision, its active sources and deliveries from one transaction.
func readBan(ctx context.Context, tx *sql.Tx, id string, now time.Time) (bans.Record, error) {
	decision, err := readDecision(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return bans.Record{}, bans.ErrNotFound
	}
	if err != nil {
		return bans.Record{}, err
	}

	sources, err := readBanSources(ctx, tx, decision.IP, now)
	if err != nil {
		return bans.Record{}, err
	}

	deliveries, err := readDeliveries(ctx, tx, decision.IP)
	if err != nil {
		return bans.Record{}, err
	}

	return bans.Record{
		Decision:   decision,
		Sources:    sources,
		Deliveries: deliveries,
	}, nil
}
