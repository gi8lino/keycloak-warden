// Package sqlite implements atomic security observations and durable action work.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
	_ "modernc.org/sqlite"
)

// Store owns one SQLite database and serializes state changes on one connection.
type Store struct {
	// db owns the single SQLite connection used for state changes.
	db *sql.DB
	// lock holds exclusive Warden ownership until the SQLite connection closes.
	lock *flock.Flock
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

	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}

	lock := flock.New(canonical+".lock", flock.SetPermissions(0o600))
	acquired, err := lock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock Warden database %q: %w", canonical, err)
	}
	if !acquired {
		return nil, fmt.Errorf("another Warden instance owns database %q", canonical)
	}

	db, err := openDatabase(canonical)
	if err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	return &Store{db: db, lock: lock, changes: make(chan struct{}, 1)}, nil
}

// openDatabase initializes SQLite after the caller has acquired exclusive Warden ownership.
func openDatabase(path string) (*sql.DB, error) {
	location := url.URL{Scheme: "file", Path: path}
	// Configure every connection, including replacements opened by database/sql.
	location.RawQuery = url.Values{
		"_pragma": {"busy_timeout(5000)", "foreign_keys(1)"},
	}.Encode()
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	// WAL persists in the database and allows readers alongside a writer.
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
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

	return db, nil
}

// Ping confirms that the underlying store can answer a query.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close releases the database after HTTP handlers and dispatch have stopped.
func (s *Store) Close() error { return errors.Join(s.db.Close(), s.lock.Close()) }

// Changes signals that a committed decision may have changed the worker's next deadline.
func (s *Store) Changes() <-chan struct{} { return s.changes }
