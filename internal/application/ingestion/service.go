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
	// Block persists the newest desired state and destination deliveries.
	Block(context.Context, string, int, time.Time, time.Time) (*decisions.Decision, error)
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

// Process validates one envelope and records a qualifying failure atomically.
func (s *Service) Process(ctx context.Context, envelope events.Envelope, now time.Time) (decision *decisions.Decision, err error) {
	event, err := normalize(envelope)
	if err != nil {
		return nil, err
	}
	if !s.rule.Matches(event) {
		return nil, nil
	}

	err = s.repository.Transact(ctx, func(tx Transaction) error {
		inserted, err := tx.RecordFailure(ctx, event, now)
		if err != nil || !inserted {
			return err
		}

		ip := event.IP.String()
		count, err := tx.CountFailures(ctx, ip, now.Add(-s.rule.Window))
		if err != nil || !s.rule.Triggered(count) {
			return err
		}

		decision, err = tx.Block(ctx, ip, count, now.Add(s.rule.Ban), now)
		return err
	})

	return decision, err
}

// normalize validates the producer contract without trusting HTTP headers.
func normalize(p events.Envelope) (event events.Event, err error) {
	if p.Version != 1 || p.Source != "keycloak" {
		return events.Event{}, ErrInvalidEvent
	}
	if !hasRequiredEventFields(p) {
		return events.Event{}, ErrInvalidEvent
	}

	event = events.Event{ID: p.ID, Source: p.Source, Kind: p.Kind}
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
