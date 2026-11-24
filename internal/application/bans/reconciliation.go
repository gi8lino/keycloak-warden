package bans

import (
	"context"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// ChangeCause identifies the application workflow that revised a decision.
type ChangeCause string

const (
	ChangeAutomatic  ChangeCause = "automatic"
	ChangeManual     ChangeCause = "manual"
	ChangeRelease    ChangeCause = "release"
	ChangeExpiry     ChangeCause = "expiry"
	ChangeReconciled ChangeCause = "reconciled"
)

// Transaction exposes the persisted facts needed to evaluate ban policy atomically.
// Its implementation commits or rolls back together with the originating operation.
type Transaction interface {
	// EnsureDecision creates the stable identity used by independent ban sources.
	EnsureDecision(context.Context, string) error
	// Source reads an existing source, including one which has already expired.
	Source(context.Context, string, SourceKind) (Source, bool, error)
	// PutSource persists the source exactly as supplied by the application.
	PutSource(context.Context, string, Source) error
	// Decision reads the current desired state for an address.
	Decision(context.Context, string) (decisions.Decision, error)
	// Sources reads the active reasons for a decision at the supplied time.
	Sources(context.Context, string, time.Time) ([]Source, error)
	// SaveDecision atomically persists a calculated state and synchronizes delivery work.
	SaveDecision(context.Context, decisions.Decision, decisions.Decision, []Source, ChangeCause, bool, []string) error
}

// MutationTransaction adds storage operations used by administrative and expiry workflows.
type MutationTransaction interface {
	Transaction
	// DecisionByID loads a persisted decision for administrative release.
	DecisionByID(context.Context, string) (decisions.Decision, error)
	// DeleteSources clears every reason for a specified address.
	DeleteSources(context.Context, string) error
	// ResetFailures advances the failed-login observation generation.
	ResetFailures(context.Context, string) error
	// ExpiredSourceIPs lists addresses that require expiry reconciliation.
	ExpiredSourceIPs(context.Context, time.Time) ([]string, error)
	// DeleteExpiredSources removes elapsed sources at the given time.
	DeleteExpiredSources(context.Context, time.Time) error
	// Record returns the decision and its sources within the transaction.
	Record(context.Context, string, time.Time) (Record, error)
}

// ExtendSource applies the non-shortening expiry policy before persisting a source.
func ExtendSource(ctx context.Context, tx Transaction, ip string, source Source) error {
	if err := tx.EnsureDecision(ctx, ip); err != nil {
		return err
	}

	previous, exists, err := tx.Source(ctx, ip, source.Kind)
	if err != nil {
		return err
	}
	if exists {
		source.ExpiresAt = ExtendExpiry(previous.ExpiresAt, source.ExpiresAt)
	}

	return tx.PutSource(ctx, ip, source)
}

// ReconcileDecision evaluates the sources in the application and persists the result.
func ReconcileDecision(
	ctx context.Context,
	tx Transaction,
	ip string,
	now time.Time,
	targets []string,
) (decisions.Decision, bool, error) {
	return ReconcileDecisionWithCause(ctx, tx, ip, now, targets, ChangeReconciled)
}

// ReconcileDecisionWithCause records why this effective revision changed.
func ReconcileDecisionWithCause(
	ctx context.Context,
	tx Transaction,
	ip string,
	now time.Time,
	targets []string,
	cause ChangeCause,
) (decisions.Decision, bool, error) {
	previous, err := tx.Decision(ctx, ip)
	if err != nil {
		return decisions.Decision{}, false, err
	}
	sources, err := tx.Sources(ctx, ip, now)
	if err != nil {
		return decisions.Decision{}, false, err
	}

	next, changed := Reconcile(previous, sources, now)
	if err := tx.SaveDecision(ctx, previous, next, sources, cause, changed, targets); err != nil {
		return decisions.Decision{}, false, err
	}

	return next, changed, nil
}
