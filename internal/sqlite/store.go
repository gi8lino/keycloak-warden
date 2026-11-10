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
	// changes coalesces committed decision changes until the worker observes them.
	changes chan struct{}
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

	// Include every table after opening the connection; later calls use SQLite's
	// lightweight default optimize mode to avoid unnecessary ANALYZE work.
	if _, err := db.ExecContext(context.Background(), "PRAGMA optimize=0x10002"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("optimize sqlite database: %w", err)
	}

	return &Store{
		db:      db,
		rule:    rule,
		targets: slices.Clone(targets),
		changes: make(chan struct{}, 1),
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

	observation := &observationTx{tx: tx, targets: s.targets}
	if err := apply(observation); err != nil {
		return err
	}
	if observation.changed {
		return s.commitDecision(tx)
	}
	return tx.Commit()
}

// Ping confirms that the underlying store can answer a query.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close releases the database after HTTP handlers and dispatch have stopped.
func (s *Store) Close() error { return s.db.Close() }

// Changes signals that a committed decision may have changed the worker's next deadline.
func (s *Store) Changes() <-chan struct{} { return s.changes }

// commitDecision wakes the worker only after the new state is visible to readers.
func (s *Store) commitDecision(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	select {
	case s.changes <- struct{}{}:
	default:
	}
	return nil
}

// Optimize refreshes SQLite query-planner statistics without rebuilding the database.
func (s *Store) Optimize(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA optimize")
	if err != nil {
		return fmt.Errorf("optimize sqlite database: %w", err)
	}
	return nil
}
