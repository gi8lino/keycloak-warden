// Package ingestion validates source events and applies detection decisions atomically.
package ingestion

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
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
	// Ban policy reads and writes share this observation transaction.
	bans.Transaction
}

// Repository executes an application operation within one atomic transaction.
type Repository interface {
	// TransactObservation atomically records a failed login and any resulting decision.
	TransactObservation(context.Context, func(Transaction) error) error
}

// Service coordinates event validation, detection, and durable decisions.
type Service struct {
	// repository provides transactional persistence for this application service.
	repository Repository
	// rule contains the validated failed-login policy.
	rule detection.Rule
	// targets identifies the configured destinations for new decisions.
	targets []string
}

// New constructs an ingestion service with a validated detection policy.
func New(repository Repository, rule detection.Rule, targets []string) (*Service, error) {
	if repository == nil {
		return nil, errors.New("ingestion repository is required")
	}
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	return &Service{repository: repository, rule: rule, targets: slices.Clone(targets)}, nil
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

	err = s.repository.TransactObservation(ctx, func(tx Transaction) error {
		var processErr error
		result, processErr = s.processFailure(ctx, tx, event, now)
		return processErr
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// processFailure records an accepted observation and applies the detection rule in one transaction.
func (s *Service) processFailure(
	ctx context.Context,
	tx Transaction,
	event events.Event,
	now time.Time,
) (Result, error) {
	result := Result{
		IP: event.IP.String(),
	}

	inserted, err := tx.RecordFailure(ctx, event, now)
	if err != nil {
		return Result{}, err
	}
	if !inserted {
		result.Outcome = OutcomeDuplicate
		return result, nil
	}

	count, err := tx.CountFailures(ctx, result.IP, now.Add(-s.rule.Window))
	if err != nil {
		return Result{}, err
	}
	result.Failures = count
	result.Threshold = s.rule.Threshold
	if !s.rule.Triggered(count) {
		result.Outcome = OutcomeBelowThreshold
		return result, nil
	}

	if err := bans.ExtendSource(ctx, tx, result.IP, bans.Source{
		Kind:      bans.SourceAutomatic,
		ExpiresAt: now.Add(s.rule.Ban),
	}); err != nil {
		return Result{}, err
	}

	decision, changed, err := bans.ReconcileDecision(ctx, tx, result.IP, now, s.targets)
	if err != nil {
		return Result{}, err
	}
	if !changed {
		result.Outcome = OutcomeUnchanged
		return result, nil
	}

	result.Outcome = OutcomeUpdated
	result.Decision = &decision

	return result, nil
}

// normalize validates the producer contract without trusting HTTP headers.
func normalize(p events.Envelope) (event events.Event, err error) {
	if p.Version != events.SchemaVersion || p.Source != events.SourceKeycloak {
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
