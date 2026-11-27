package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
)

// ManagedTargets returns destinations that still own a banned decision or an
// unacknowledged revision.
func (s *Store) ManagedTargets(ctx context.Context) ([]string, error) {
	return managedTargets(ctx, s.db)
}

// managedTargets reads obligations using the caller's connection or transaction.
func managedTargets(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]string, error) {
	rows, err := q.QueryContext(ctx, `
SELECT DISTINCT q.destination
FROM deliveries AS q
JOIN decisions AS d USING (ip)
WHERE d.state = 'banned'
    OR q.acknowledged < d.revision
ORDER BY q.destination
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// BindTargetIdentities protects outstanding obligations from destination reassignment.
// Startup calls this before any worker or HTTP listener begins.
func (s *Store) BindTargetIdentities(ctx context.Context, identities map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := bindTargetIdentities(ctx, tx, identities); err != nil {
		return err
	}
	return tx.Commit()
}

// bindTargetIdentities validates and writes identities in the caller's transaction.
func bindTargetIdentities(ctx context.Context, tx *sql.Tx, identities map[string]string) error {
	managed, err := managedTargets(ctx, tx)
	if err != nil {
		return err
	}
	for _, name := range managed {
		var previous string
		err := tx.QueryRowContext(ctx, "SELECT identity FROM target_identities WHERE name = ?", name).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("destination %q has existing obligations without an identity; reconcile with the previous deployment first", name)
		}
		if err != nil {
			return err
		}
		if identities[name] != previous {
			return fmt.Errorf("destination %q has changed identity; reconcile its obligations first", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(identities)) {
		if identities[name] == "" {
			return fmt.Errorf("destination %q has no identity", name)
		}
		if _, err := tx.ExecContext(
			ctx,
			`
INSERT INTO target_identities (name, identity)
VALUES (?, ?)
ON CONFLICT (name) DO UPDATE SET identity = excluded.identity
`,
			name,
			identities[name],
		); err != nil {
			return err
		}
	}
	return nil
}
