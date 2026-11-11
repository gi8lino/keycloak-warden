package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
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

// InspectMany returns requested decision records with sources and deliveries from one read-only transaction.
func InspectMany(ctx context.Context, path string, ids []string) ([]bans.Record, error) {
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

	now := time.Now()
	records := make([]bans.Record, 0, len(ids))
	for _, id := range ids {
		record, err := readBan(ctx, tx, id, now)
		if err != nil {
			return nil, fmt.Errorf("inspect decision %q: %w", id, err)
		}
		records = append(records, record)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

// ListActiveBans reads active bans and their sources from an existing read-only database.
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

	records, err := listBans(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	return records, tx.Commit()
}
