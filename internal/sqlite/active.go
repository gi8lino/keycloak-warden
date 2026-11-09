package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// openReader opens an existing SQLite database in read-only mode.
func openReader(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	location := url.URL{Scheme: "file", Path: absolute, RawQuery: "mode=ro"}
	return sql.Open("sqlite", location.String())
}

// Inspect returns a consistent view of a decision and its pending deliveries.
func Inspect(ctx context.Context, path, id string) (decisions.Inspection, error) {
	views, err := InspectMany(ctx, path, []string{id})
	if err != nil {
		return decisions.Inspection{}, err
	}
	return views[0], nil
}

// InspectMany returns the requested decisions and deliveries from one read-only transaction.
func InspectMany(ctx context.Context, path string, ids []string) ([]decisions.Inspection, error) {
	db, err := openReader(path)
	if err != nil {
		return nil, err
	}
	defer db.Close() // nolint:errcheck

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	views := make([]decisions.Inspection, 0, len(ids))
	for _, id := range ids {
		view, err := inspectTx(ctx, tx, id)
		if err != nil {
			return nil, fmt.Errorf("inspect decision %q: %w", id, err)
		}
		views = append(views, view)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return views, nil
}

// inspectTx reads a decision and its deliveries within an existing transaction.
func inspectTx(ctx context.Context, tx *sql.Tx, id string) (decisions.Inspection, error) {
	view := decisions.Inspection{Deliveries: []decisions.Acknowledgement{}}

	decision := &view.Decision
	var expires int64
	err := tx.QueryRowContext(ctx, `
SELECT id, revision, ip, active, expires, failures
FROM decisions
WHERE id = ?
`, id).Scan(&decision.ID, &decision.Revision, &decision.IP, &decision.Active, &expires, &decision.Failures)
	if err != nil {
		return view, err
	}
	decision.ExpiresAt = time.UnixMilli(expires).UTC()

	rows, err := tx.QueryContext(ctx, `
SELECT destination, acknowledged
FROM deliveries
WHERE ip = ?
ORDER BY destination
`, decision.IP)
	if err != nil {
		return view, err
	}

	for rows.Next() {
		var ack decisions.Acknowledgement
		if err := rows.Scan(&ack.Destination, &ack.Revision); err != nil {
			_ = rows.Close()
			return view, err
		}
		view.Deliveries = append(view.Deliveries, ack)
	}

	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return view, err
	}

	if err := rows.Close(); err != nil {
		return view, err
	}

	return view, nil
}

// ListActiveBans reads active blocks with their automatic and manual sources.
// It opens the existing database read-only and never starts the delivery worker.
func ListActiveBans(ctx context.Context, path string, now time.Time) ([]bans.Ban, error) {
	db, err := openReader(path)
	if err != nil {
		return nil, err
	}
	defer db.Close() // nolint:errcheck

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	views, err := listBans(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	return views, tx.Commit()
}
