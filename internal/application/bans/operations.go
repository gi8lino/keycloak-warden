package bans

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Writer executes a domain workflow inside one atomic persistence transaction.
type Writer interface {
	TransactBan(context.Context, func(MutationTransaction) error) error
}

// ApplyManualBan records a manual reason and reconciles its desired state atomically.
func ApplyManualBan(ctx context.Context, store Writer, ip string, until time.Time, reason string, now time.Time, targets []string) (Record, error) {
	var record Record
	err := store.TransactBan(ctx, func(tx MutationTransaction) error {
		if err := ExtendSource(ctx, tx, ip, Source{
			Kind:      SourceManual,
			ExpiresAt: until,
			Reason:    reason,
		}); err != nil {
			return err
		}

		decision, _, err := ReconcileDecision(ctx, tx, ip, now, targets)
		if err != nil {
			return err
		}
		record, err = tx.Record(ctx, decision.ID, now)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// ReleaseAllSources clears active reasons and starts a fresh observation generation.
func ReleaseAllSources(ctx context.Context, store Writer, id string, now time.Time, targets []string) (Record, error) {
	var record Record
	err := store.TransactBan(ctx, func(tx MutationTransaction) error {
		current, err := tx.DecisionByID(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if current.State != decisions.StateBanned || !current.ExpiresAt.After(now) {
			return ErrNotFound
		}
		if err := tx.DeleteSources(ctx, current.IP); err != nil {
			return err
		}
		// Retain producer IDs for replay protection while resetting the count.
		if err := tx.ResetFailures(ctx, current.IP); err != nil {
			return err
		}

		next, _, err := ReconcileDecision(ctx, tx, current.IP, now, targets)
		if err != nil {
			return err
		}
		record, err = tx.Record(ctx, next.ID, now)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// ExpireSources atomically drops elapsed sources and records effective releases.
func ExpireSources(ctx context.Context, store Writer, now time.Time, targets []string) ([]decisions.Decision, error) {
	var released []decisions.Decision
	err := store.TransactBan(ctx, func(tx MutationTransaction) error {
		ips, err := tx.ExpiredSourceIPs(ctx, now)
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			return nil
		}
		if err := tx.DeleteExpiredSources(ctx, now); err != nil {
			return err
		}
		for _, ip := range ips {
			decision, changed, err := ReconcileDecision(ctx, tx, ip, now, targets)
			if err != nil {
				return err
			}
			if changed && decision.State == decisions.StateUnbanned {
				released = append(released, decision)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
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
