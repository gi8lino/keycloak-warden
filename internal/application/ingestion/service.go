// Package ingestion validates source events and applies detection decisions atomically.
package ingestion

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
)

// ErrInvalidEvent identifies an event rejected by the application contract.
var ErrInvalidEvent = errors.New("invalid security event")

// Transaction provides atomic, storage-independent observation operations.
type Transaction interface {
	// RecordFailure deduplicates an occurrence and reports whether it was new.
	RecordFailure(context.Context, events.Event, time.Time) (bool, error)
	// CountFailures returns observed failures in the active sliding window.
	CountFailures(context.Context, string, time.Time) (int, error)
	// Block persists the automatic source and returns a decision only if its desired state changed.
	Block(context.Context, string, time.Time, time.Time) (*decisions.Decision, error)
}

// Repository executes an application operation within one atomic transaction.
type Repository interface {
	Transact(context.Context, func(Transaction) error) error
}

// Service coordinates event validation, detection, and durable decisions.
type Service struct {
	// repository provides transactional persistence for this application service.
	repository Repository
	// rule contains the validated failed-login policy.
	rule detection.Rule
}

// New constructs an ingestion service with a validated detection policy.
func New(repository Repository, rule detection.Rule) (*Service, error) {
	if repository == nil {
		return nil, errors.New("ingestion repository is required")
	}
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	return &Service{repository: repository, rule: rule}, nil
}

// Process validates an envelope and returns the committed detection outcome.
func (s *Service) Process(
	ctx context.Context,
	envelope events.Envelope,
	now time.Time,
) (result Result, err error) {
	event, err := normalize(envelope)
	if err != nil {
		return Result{}, err
	}

	result = Result{Outcome: OutcomeIgnored}
	if event.IP.IsValid() {
		result.IP = event.IP.String()
	}
	if !s.rule.Matches(event) {
		result.Reason = "unsupported_event_type"
		if !event.IP.IsValid() {
			result.Reason = "missing_ip"
		}
		return result, nil
	}

	err = s.repository.Transact(ctx, func(tx Transaction) error {
		inserted, err := tx.RecordFailure(ctx, event, now)
		if err != nil {
			return err
		}
		if !inserted {
			result.Outcome = OutcomeDuplicate
			return nil
		}

		count, err := tx.CountFailures(ctx, result.IP, now.Add(-s.rule.Window))
		if err != nil {
			return err
		}
		result.Failures = count
		result.Threshold = s.rule.Threshold
		if !s.rule.Triggered(count) {
			result.Outcome = OutcomeBelowThreshold
			return nil
		}

		decision, err := tx.Block(ctx, result.IP, now.Add(s.rule.Ban), now)
		if err != nil {
			return err
		}
		if decision == nil {
			result.Outcome = OutcomeUnchanged
			return nil
		}
		result.Outcome = OutcomeUpdated
		result.Decision = decision
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// normalize validates the producer contract without trusting HTTP headers.
func normalize(p events.Envelope) (event events.Event, err error) {
	if p.Version != 1 || p.Source != "keycloak" {
		return events.Event{}, ErrInvalidEvent
	}

	if !hasRequiredEventFields(p) {
		return events.Event{}, ErrInvalidEvent
	}

	event = events.Event{
		ID:     p.ID,
		Source: p.Source,
		Kind:   p.Kind,
	}

	if p.IP != "" {
		ip, err := ipaddress.ParseUnicast(p.IP)
		if err != nil {
			return events.Event{}, ErrInvalidEvent
		}
		event.IP = ip.Unmap()
	}

	return event, nil
}

// hasRequiredEventFields checks the identity, native event type and producer timestamp.
func hasRequiredEventFields(event events.Envelope) bool {
	return strings.TrimSpace(event.ID) != "" &&
		strings.TrimSpace(event.Kind) != "" &&
		!event.Timestamp.IsZero()
}
