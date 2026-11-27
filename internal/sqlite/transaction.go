package sqlite

import (
	"context"
	"database/sql"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// transaction implements both application transaction interfaces over one SQL transaction.
// Change flags request independent worker wakeups after a successful commit.
type transaction struct {
	// tx contains all observation, source, and decision changes until commit.
	tx *sql.Tx
	// changed records whether the transaction modified source or decision state.
	changed bool
	// notificationChanged records whether the transaction queued incident deliveries.
	notificationChanged bool
}

var (
	_ ingestion.Transaction    = (*transaction)(nil)
	_ bans.MutationTransaction = (*transaction)(nil)
)

// TransactObservation runs observation and detection in one transaction.
// Callback errors roll back all changes; committed work wakes its corresponding worker.
func (s *Store) TransactObservation(ctx context.Context, apply func(ingestion.Transaction) error) error {
	return s.transact(ctx, func(tx *transaction) error {
		return apply(tx)
	})
}

// TransactDecision runs ban source and decision mutations in one transaction.
// Callback errors roll back all changes; committed decision changes wake the worker.
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
	if err := tx.Commit(); err != nil {
		return err
	}
	if state.changed {
		wake(s.changes)
	}
	if state.notificationChanged {
		wake(s.notificationChanges)
	}
	return nil
}

// commitDecision wakes the worker only after the new state is visible to readers.
func (s *Store) commitDecision(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	wake(s.changes)
	return nil
}

// wake coalesces committed changes without blocking the writer.
func wake(changes chan struct{}) {
	select {
	case changes <- struct{}{}:
	default:
	}
}
