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
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// Transaction provides atomic, storage-independent observation operations.
type Transaction interface {
	// RecordEvent deduplicates a normalized envelope and reports whether it was new.
	RecordEvent(context.Context, events.Envelope, time.Time, bool) (bool, error)
	// CountMatches returns observations matching a rule within its window.
	CountMatches(context.Context, detection.MatchQuery) (int, error)
	// RecordIncident stores a named threshold hit and queues selected notifications.
	RecordIncident(context.Context, model.Incident, []string) (int64, error)
	// Ban policy reads and writes share this observation transaction.
	bans.Transaction
}

// Repository executes an application operation within one atomic transaction.
type Repository interface {
	// TransactObservation atomically records an event and any resulting incidents or decision.
	TransactObservation(context.Context, func(Transaction) error) error
}

// Service coordinates event validation, detection, and durable decisions.
type Service struct {
	// repository provides transactional persistence for this application service.
	repository Repository
	// rules contains the validated detection policies.
	rules []detection.Rule
	// targets identifies the configured destinations for new decisions.
	targets []string
	// policy controls enforcement admission.
	policy bans.Policy
}

// New constructs ingestion with validated named detection rules.
func New(repository Repository, rules []detection.Rule, targets []string, policy bans.Policy) (*Service, error) {
	if repository == nil {
		return nil, errors.New("ingestion repository is required")
	}

	if err := detection.ValidateRules(rules); err != nil {
		return nil, err
	}

	rules = slices.Clone(rules)
	for i := range rules {
		rules[i].Selector.Events = slices.Clone(rules[i].Selector.Events)
		rules[i].Selector.Operations = slices.Clone(rules[i].Selector.Operations)
		rules[i].Selector.Resources = slices.Clone(rules[i].Selector.Resources)
		rules[i].Actions.Notify = slices.Clone(rules[i].Actions.Notify)
	}

	slices.SortFunc(rules, func(a, b detection.Rule) int { return strings.Compare(a.Name, b.Name) })

	return &Service{
		repository: repository,
		rules:      rules,
		targets:    slices.Clone(targets),
		policy:     policy,
	}, nil
}

// Process validates an envelope and returns the committed detection outcome.
func (s *Service) Process(
	ctx context.Context,
	envelope events.Envelope,
	clock func() time.Time,
) (result Result, err error) {
	event, err := events.Normalize(envelope)
	if err != nil {
		return Result{}, err
	}

	result = Result{Outcome: OutcomeIgnored, IP: event.Address()}
	matching := make([]detection.Rule, 0, len(s.rules))
	protected := s.policy.Protection.Contains(event.IPAddress())
	excluded := false

	for _, rule := range s.rules {
		if !rule.Matches(event) {
			continue
		}

		if rule.Actions.Ban > 0 && protected {
			excluded = true
			continue
		}
		matching = append(matching, rule)
	}

	if len(matching) == 0 {
		if excluded {
			result.Outcome = OutcomeProtected
		} else if s.missingIP(event) {
			result.Reason = "missing_ip"
		} else {
			result.Reason = "unsupported_event_type"
		}
		return result, nil
	}

	err = s.repository.TransactObservation(ctx, func(tx Transaction) error {
		var processErr error
		result, processErr = s.processMatches(ctx, tx, event, matching, clock(), !protected)
		return processErr
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// missingIP reports whether an otherwise matching rule requires a missing IP.
func (s *Service) missingIP(event events.Envelope) bool {
	if event.IPAddress().IsValid() {
		return false
	}
	for _, rule := range s.rules {
		if rule.Aggregation.RequiresIP() && rule.Selector.Matches(event) {
			return true
		}
	}

	return false
}

// processMatches evaluates every matching rule and reconciles at most one ban.
func (s *Service) processMatches(
	ctx context.Context,
	tx Transaction,
	event events.Envelope,
	rules []detection.Rule,
	now time.Time,
	banEligible bool,
) (Result, error) {
	result := Result{IP: event.Address(), Outcome: OutcomeBelowThreshold}
	inserted, err := tx.RecordEvent(ctx, event, now, banEligible)
	if err != nil {
		return Result{}, err
	}
	if !inserted {
		result.Outcome = OutcomeDuplicate
		return result, nil
	}

	var longest time.Duration
	notificationDestinations := make(map[string][]string)
	for _, rule := range rules {
		query := rule.Query(event, now)

		count, err := tx.CountMatches(ctx, query)
		if err != nil {
			return Result{}, err
		}
		result.Evaluations = append(result.Evaluations, detection.Evaluation{
			Rule:      rule.Name,
			Count:     count,
			Threshold: rule.Aggregation.Threshold,
		})

		if !rule.Triggered(count) {
			continue
		}

		if result.Outcome == OutcomeBelowThreshold {
			result.Outcome = OutcomeThresholdMet
		}

		crossing, err := detection.Crossed(ctx, tx, rule, query, event.ID)
		if err != nil {
			return Result{}, err
		}

		if crossing {
			result.Outcome = OutcomeIncident
			result.Incidents = append(result.Incidents, newIncident(rule, event, now, count, s.policy.ObserveOnly))
			if len(rule.Actions.Notify) > 0 {
				notificationDestinations[rule.Name] = rule.Actions.Notify
			}
		}

		if rule.Actions.Ban > longest {
			longest = rule.Actions.Ban
		}
	}

	var effective *model.Decision
	if longest > 0 {
		result, effective, err = s.applyBan(ctx, tx, result, now, longest)
		if err != nil {
			return Result{}, err
		}
	}

	for i := range result.Incidents {
		incident := &result.Incidents[i]
		if incident.BanUntil != nil && longest > 0 {
			expiry := now.Add(longest).UTC()
			incident.EffectiveBanUntil = &expiry

			if effective != nil {
				incident.DecisionID = effective.ID
				incident.DecisionRevision = effective.Revision
			}
		}

		id, err := tx.RecordIncident(ctx, *incident, notificationDestinations[incident.Rule])
		if err != nil {
			return Result{}, err
		}

		incident.ID = id
	}

	return result, nil
}

// applyBan records or reconciles the longest qualifying automatic ban.
func (s *Service) applyBan(
	ctx context.Context,
	tx Transaction,
	result Result,
	now time.Time,
	duration time.Duration,
) (Result, *model.Decision, error) {
	if s.policy.ObserveOnly {
		result.Outcome = OutcomeObserved
		return result, nil, nil
	}

	decision, changed, err := bans.ApplyAutomaticBan(ctx, tx, result.IP, now.Add(duration), now, s.targets)
	if err != nil {
		return Result{}, nil, err
	}
	if !changed {
		result.Outcome = OutcomeUnchanged
		return result, &decision, nil
	}

	result.Outcome = OutcomeUpdated
	result.Decision = &decision

	return result, &decision, nil
}

// newIncident snapshots a named rule hit without storing arbitrary event details.
func newIncident(rule detection.Rule, event events.Envelope, now time.Time, count int, observeOnly bool) model.Incident {
	query := rule.Query(event, now)

	incident := model.Incident{
		Rule:          rule.Name,
		GroupBy:       query.GroupBy,
		GroupKey:      query.Key,
		IdentityRealm: query.IdentityRealm,
		Distinct:      query.Distinct,
		Window:        rule.Aggregation.Window.String(),
		Source:        event.Source,
		EventID:       event.ID,
		EventKind:     event.Kind,
		EventType:     event.EventType(),
		RealmID:       event.RealmID(),
		ActorRealmID:  event.ActorRealmID(),
		UserID:        event.UserID(),
		ClientID:      event.ClientID(),
		IP:            event.Address(),
		Error:         event.ErrorCode(),
		OperationType: event.OperationType(),
		ResourceType:  event.ResourceType(),
		ResourcePath:  event.ResourcePath(),
		EventAt:       event.Timestamp,
		At:            now,
		Count:         count,
		Threshold:     rule.Aggregation.Threshold,
		ObserveOnly:   observeOnly && rule.Actions.Ban > 0,
	}

	if rule.Actions.Ban > 0 {
		expiry := now.Add(rule.Actions.Ban).UTC()
		incident.BanUntil = &expiry
	}

	return incident
}
