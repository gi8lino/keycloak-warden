package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// Store fulfills the application's atomic ban administration contract.
var _ bans.Store = (*Store)(nil)

// ListActive returns all currently active effective bans, with source and delivery details.
func (s *Store) ListActive(ctx context.Context, now time.Time) ([]model.Record, error) {
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
func listBans(ctx context.Context, tx *sql.Tx, now time.Time) ([]model.Record, error) {
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
) (list []model.Record, byIP map[string]int, err error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, revision, ip, state, expires
FROM decisions
WHERE state = ? AND expires > ?
ORDER BY ip
`, model.DecisionBanned, now.UnixMilli())
	if err != nil {
		return nil, nil, err
	}

	list = []model.Record{}
	byIP = make(map[string]int)
	for rows.Next() {
		record := model.Record{
			Sources:    []model.Source{},
			Deliveries: []model.Acknowledgement{},
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
	list []model.Record,
	byIP map[string]int,
	now time.Time,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT s.ip, s.kind, s.expires, s.reason
FROM ban_sources AS s
JOIN decisions AS d ON d.ip = s.ip
WHERE d.state = ? AND d.expires > ? AND s.expires > ?
ORDER BY s.ip, s.kind
`, model.DecisionBanned, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return err
	}

	for rows.Next() {
		var ip string
		var source model.Source
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
	list []model.Record,
	byIP map[string]int,
	now time.Time,
) error {
	rows, err := tx.QueryContext(ctx, `
SELECT q.ip, q.destination, q.acknowledged
FROM deliveries AS q
JOIN decisions AS d ON d.ip = q.ip
WHERE d.state = ? AND d.expires > ?
ORDER BY q.ip, q.destination
`, model.DecisionBanned, now.UnixMilli())
	if err != nil {
		return err
	}

	for rows.Next() {
		var ip string
		var ack model.Acknowledgement
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

// GetDecision returns the persisted decision and the newest bounded history page.
func (s *Store) GetDecision(ctx context.Context, id string, now time.Time) (model.Record, error) {
	bounds, err := bans.NewHistoryPage(1, 0)
	if err != nil {
		return model.Record{}, err
	}
	return s.GetDecisionPage(ctx, id, now, bounds)
}

// GetDecisionPage returns one consistent snapshot of a decision and its history page.
func (s *Store) GetDecisionPage(
	ctx context.Context,
	id string,
	now time.Time,
	page bans.HistoryPage,
) (model.Record, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return model.Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := readBan(ctx, tx, id, now)
	if err != nil {
		return model.Record{}, err
	}
	if page.ThroughRevision == 0 {
		page.ThroughRevision = record.Decision.Revision
	}
	var hasMore bool
	record.DeliveryHistory, hasMore, err = readDeliveryHistory(ctx, tx, record.Decision.IP, page)
	if err != nil {
		return model.Record{}, err
	}
	record.HistoryPage = page.Number
	if hasMore {
		record.HistoryNextPage = page.Number + 1
	}
	return record, tx.Commit()
}

// readBan loads a decision, its active sources and deliveries from one transaction.
func readBan(ctx context.Context, tx *sql.Tx, id string, now time.Time) (model.Record, error) {
	decision, err := readDecision(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Record{}, bans.ErrNotFound
	}
	if err != nil {
		return model.Record{}, err
	}

	sources, err := readBanSources(ctx, tx, decision.IP, now)
	if err != nil {
		return model.Record{}, err
	}

	current, err := readCurrentDeliveries(ctx, tx, decision.IP, decision.Revision)
	if err != nil {
		return model.Record{}, err
	}

	changes, err := readSourceChanges(ctx, tx, decision.IP)
	if err != nil {
		return model.Record{}, err
	}

	deliveries, err := readDeliveries(ctx, tx, decision.IP)
	if err != nil {
		return model.Record{}, err
	}

	return model.Record{
		Decision:          decision,
		Sources:           sources,
		SourceChanges:     changes,
		CurrentDeliveries: current,
		Deliveries:        deliveries,
	}, nil
}
