package bans

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// Writer executes a domain workflow inside one atomic persistence transaction.
type Writer interface {
	// TransactDecision atomically applies source changes and decision reconciliation.
	TransactDecision(context.Context, func(MutationTransaction) error) error
}

// ApplyManualBan records a manual reason and reconciles its desired state atomically.
func ApplyManualBan(
	ctx context.Context,
	store Writer,
	ip string,
	until time.Time,
	reason string,
	now time.Time,
	targets []string,
) (Record, error) {
	var record Record
	err := store.TransactDecision(ctx, func(tx MutationTransaction) error {
		var err error
		record, err = applyManualBan(ctx, tx, ip, until, reason, now, targets)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// applyManualBan changes the manual source and builds the resulting record in one transaction.
func applyManualBan(
	ctx context.Context,
	tx MutationTransaction,
	ip string,
	until time.Time,
	reason string,
	now time.Time,
	targets []string,
) (Record, error) {
	if err := ExtendSource(ctx, tx, ip, Source{
		Kind:      SourceManual,
		ExpiresAt: until,
		Reason:    reason,
	}); err != nil {
		return Record{}, err
	}

	decision, _, err := ReconcileDecisionWithCause(ctx, tx, ip, now, targets, ChangeManual)
	if err != nil {
		return Record{}, err
	}
	return tx.Record(ctx, decision.ID, now)
}

// ReleaseAllSources clears active reasons and starts a fresh observation generation.
func ReleaseAllSources(
	ctx context.Context,
	store Writer,
	id string,
	now time.Time,
	targets []string,
) (Record, error) {
	var record Record
	err := store.TransactDecision(ctx, func(tx MutationTransaction) error {
		var err error
		record, err = releaseAllSources(ctx, tx, id, now, targets)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// releaseAllSources validates the requested release and updates its sources and decision atomically.
func releaseAllSources(
	ctx context.Context,
	tx MutationTransaction,
	id string,
	now time.Time,
	targets []string,
) (Record, error) {
	current, err := tx.DecisionByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}

	if current.State != decisionstate.StateBanned || !current.ExpiresAt.After(now) {
		return Record{}, ErrNotFound
	}

	if err := tx.DeleteSources(ctx, current.IP); err != nil {
		return Record{}, err
	}

	// Retain producer IDs for replay protection while resetting the count.
	if err := tx.ResetFailures(ctx, current.IP); err != nil {
		return Record{}, err
	}

	next, _, err := ReconcileDecisionWithCause(ctx, tx, current.IP, now, targets, ChangeRelease)
	if err != nil {
		return Record{}, err
	}

	return tx.Record(ctx, next.ID, now)
}

// ExpireSources atomically drops elapsed sources and records effective releases.
func ExpireSources(
	ctx context.Context,
	store Writer,
	now time.Time,
	targets []string,
) ([]decisions.Decision, error) {
	var released []decisions.Decision
	err := store.TransactDecision(ctx, func(tx MutationTransaction) error {
		var err error
		released, err = expireSources(ctx, tx, now, targets)
		return err
	})
	if err != nil {
		return nil, err
	}

	return released, nil
}

// expireSources reconciles all decisions affected by elapsed sources in the same transaction.
func expireSources(
	ctx context.Context,
	tx MutationTransaction,
	now time.Time,
	targets []string,
) ([]decisions.Decision, error) {
	ips, err := tx.ExpiredSourceIPs(ctx, now)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, nil
	}

	if err := tx.DeleteExpiredSources(ctx, now); err != nil {
		return nil, err
	}

	var released []decisions.Decision
	for _, ip := range ips {
		decision, changed, err := ReconcileDecisionWithCause(ctx, tx, ip, now, targets, ChangeExpiry)
		if err != nil {
			return nil, err
		}
		if changed && decision.State == decisionstate.StateUnbanned {
			released = append(released, decision)
		}
	}

	return released, nil
}

// ExpiryService owns the configured destination list for expiry reconciliation.
type ExpiryService struct {
	// store runs expiry operations within a single transaction.
	store Writer
	// targets are the configured destination identifiers for new revisions.
	targets []string
}

// NewExpiryService constructs the application expiry workflow.
func NewExpiryService(store Writer, targets []string) (*ExpiryService, error) {
	if store == nil {
		return nil, errors.New("expiry store is required")
	}

	return &ExpiryService{store: store, targets: slices.Clone(targets)}, nil
}

// Expire reconciles all elapsed sources in one transaction.
func (s *ExpiryService) Expire(ctx context.Context, now time.Time) ([]decisions.Decision, error) {
	return ExpireSources(ctx, s.store, now, s.targets)
}
