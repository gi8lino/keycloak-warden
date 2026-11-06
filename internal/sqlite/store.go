// Package sqlite implements atomic security observations and durable action work.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"

	_ "modernc.org/sqlite"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// Store owns one SQLite database and serializes state changes on one connection.
type Store struct {
	// db owns the single SQLite connection used for state changes.
	db *sql.DB
	// rule contains the validated failed-login policy.
	rule detection.Rule
	// targets lists the configured destinations for new decisions.
	targets []string
}

// Open opens or creates the database and runs embedded, versioned migrations.
func Open(path string, rule detection.Rule, targets []string) (*Store, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}

	location := url.URL{Scheme: "file", Path: absolute}
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
PRAGMA busy_timeout = 5000;
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
`); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := validateTargets(db, targets); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{
		db:      db,
		rule:    rule,
		targets: slices.Clone(targets),
	}, nil
}

// validateTargets refuses to abandon pending ownership of external bans.
func validateTargets(db *sql.DB, targets []string) error {
	rows, err := db.Query(`
SELECT DISTINCT q.destination
FROM deliveries AS q
JOIN decisions AS d USING (ip)
WHERE d.active = 1 OR q.acknowledged < d.revision
`)
	if err != nil {
		return err
	}
	defer rows.Close() // nolint:errcheck

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if !slices.Contains(targets, name) {
			return fmt.Errorf("destination %q has managed decisions; keep it configured until release", name)
		}
	}
	return rows.Err()
}

// Transact runs the application observation workflow in one SQLite transaction.
func (s *Store) Transact(ctx context.Context, apply func(ingestion.Transaction) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := apply(observationTx{tx: tx, targets: s.targets}); err != nil {
		return err
	}
	return tx.Commit()
}

// Ping confirms that the underlying store can answer a query.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close releases the database after HTTP handlers and dispatch have stopped.
func (s *Store) Close() error { return s.db.Close() }
