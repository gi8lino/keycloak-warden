// Package sqlite implements atomic security observations and durable action work.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store owns one SQLite database and serializes state changes on one connection.
type Store struct {
	// db owns the single SQLite connection used for state changes.
	db *sql.DB
	// changes coalesces committed decision changes until the worker observes them.
	changes chan struct{}
}

// Open opens or creates the database and runs embedded, versioned migrations.
func Open(path string) (*Store, error) {
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

	// Include every table after opening the connection; later calls use SQLite's
	// lightweight default optimize mode to avoid unnecessary ANALYZE work.
	if _, err := db.ExecContext(context.Background(), "PRAGMA optimize=0x10002"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("optimize sqlite database: %w", err)
	}

	return &Store{
		db:      db,
		changes: make(chan struct{}, 1),
	}, nil
}

// Ping confirms that the underlying store can answer a query.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close releases the database after HTTP handlers and dispatch have stopped.
func (s *Store) Close() error { return s.db.Close() }

// Changes signals that a committed decision may have changed the worker's next deadline.
func (s *Store) Changes() <-chan struct{} { return s.changes }
