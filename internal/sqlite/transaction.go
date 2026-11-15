package sqlite

import (
	"context"
	"database/sql"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// transaction implements both application transaction interfaces over one SQL transaction.
// The changed flag requests a worker notification after a successful commit.
type transaction struct {
	// tx contains all observation, source, and decision changes until commit.
	tx *sql.Tx
	// changed records whether the transaction modified source or decision state.
	changed bool
}

// Keep the application-facing capabilities narrow even though SQLite uses one type.
var (
	_ ingestion.Transaction    = (*transaction)(nil)
	_ bans.MutationTransaction = (*transaction)(nil)
)

// TransactObservation executes failure observation and detection as one atomic
// SQLite transaction.
//
// The apply callback receives the transaction operations required by the
// ingestion service. This allows the application to coordinate multiple
// dependent operations without exposing SQLite details or managing the
// transaction lifecycle itself.
//
// If apply returns an error, all changes are rolled back. Otherwise, the
// transaction is committed. Committed decision changes notify the delivery
// worker so it can process the updated state.
func (s *Store) TransactObservation(ctx context.Context, apply func(ingestion.Transaction) error) error {
	return s.transact(ctx, func(tx *transaction) error {
		return apply(tx)
	})
}

// TransactDecision executes ban source and decision mutations as one atomic
// SQLite transaction.
//
// The apply callback receives the transaction operations required by the
// ban application services. This allows the application to orchestrate
// workflows such as manual bans, releases, and expiry while keeping all
// related persistence changes within the same transaction.
//
// If apply returns an error, all changes are rolled back. Otherwise, the
// transaction is committed. Committed decision changes notify the delivery
// worker so it can reconcile the updated state.
func (s *Store) TransactDecision(ctx context.Context, apply func(bans.MutationTransaction) error) error {
	return s.transact(ctx, func(tx *transaction) error {
		return apply(tx)
	})
}

// transact shares the commit, rollback, and worker-notification lifecycle.
func (s *Store) transact(ctx context.Context, apply func(*transaction) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	state := &transaction{tx: tx}
	if err := apply(state); err != nil {
		return err
	}
	if state.changed {
		return s.commitDecision(tx)
	}
	return tx.Commit()
}

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
