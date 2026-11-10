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

// inspectTx reads one decision and its deliveries within an existing transaction.
func inspectTx(ctx context.Context, tx *sql.Tx, id string) (decisions.Inspection, error) {
	decision, err := readDecision(ctx, tx, id)
	if err != nil {
		return decisions.Inspection{}, err
	}

	deliveries, err := readDeliveries(ctx, tx, decision.IP)
	if err != nil {
		return decisions.Inspection{}, err
	}

	return decisions.Inspection{Decision: decision, Deliveries: deliveries}, nil
}

// ListActiveBans reads active blocks with their automatic and manual sources.
// It opens the existing database read-only and never starts the delivery worker.
func ListActiveBans(ctx context.Context, path string, now time.Time) ([]bans.Record, error) {
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
