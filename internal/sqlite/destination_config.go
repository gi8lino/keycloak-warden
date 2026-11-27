package sqlite

import (
	"context"
	"database/sql"

	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
)

// ConfigureDestinations atomically binds both delivery workflows and reconciles enforcement budgets.
// Call before starting listeners or workers, after validating application admission.
func (s *Store) ConfigureDestinations(ctx context.Context, enforcementIdentities, notificationIdentities map[string]string, reconcile func(enforcement.AttemptLimitReconciler) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := bindTargetIdentities(ctx, tx, enforcementIdentities); err != nil {
		return err
	}
	if err := bindNotificationIdentities(ctx, tx, notificationIdentities); err != nil {
		return err
	}
	if err := reconcile(attemptReconciler{tx: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

// attemptReconciler keeps all startup budget updates in the configuration transaction.
type attemptReconciler struct {
	// tx is the open startup transaction.
	tx *sql.Tx
}

// ReconcileAttemptLimit persists the policy's statuses inside the startup transaction.
func (r attemptReconciler) ReconcileAttemptLimit(ctx context.Context, name string, limit enforcement.AttemptLimit) error {
	return reconcileAttemptLimit(ctx, r.tx, name, limit)
}
