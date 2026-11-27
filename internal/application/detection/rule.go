package detection

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

const (
	// GroupIP aggregates events by canonical address across realms.
	GroupIP = "ip"
	// GroupUser aggregates events by realm-scoped user ID.
	GroupUser = "user-id"
	// GroupRealm aggregates events by the affected realm.
	GroupRealm = "realm"
)

// Rule describes one named detection policy.
type Rule struct {
	// Name identifies the rule in persisted incidents.
	Name string `yaml:"-"`
	// Selector identifies eligible security events.
	Selector Selector `yaml:"selector"`
	// Aggregation determines how eligible events are counted.
	Aggregation Aggregation `yaml:"aggregation"`
	// Actions configures additional effects; incidents are always recorded.
	Actions Actions `yaml:"actions"`
}

// Selector matches event categories and native metadata.
type Selector struct {
	// Kind selects user or administrative events.
	Kind string `yaml:"kind"`
	// Events selects native user event types.
	Events []string `yaml:"events"`
	// Operations selects administrative operation types.
	Operations []string `yaml:"operations"`
	// Resources selects administrative resource types.
	Resources []string `yaml:"resources"`
	// SuccessOnly excludes events with a native error code.
	SuccessOnly bool `yaml:"success-only"`
}

// Aggregation defines a sliding counting window.
type Aggregation struct {
	// GroupBy selects the aggregation key.
	GroupBy string `yaml:"group-by"`
	// Distinct optionally counts distinct IPs or realm-scoped users.
	Distinct string `yaml:"distinct"`
	// Threshold is the minimum qualifying count.
	Threshold int `yaml:"threshold"`
	// Window is the observation counting window.
	Window time.Duration `yaml:"window"`
}

// Actions defines optional effects beyond incident recording.
type Actions struct {
	// Ban is the requested block duration; zero disables enforcement.
	Ban time.Duration `yaml:"ban"`
	// Notify identifies incident notification destinations by configured webhook name.
	Notify []string `yaml:"notify"`
}

// MaxWindow bounds counting windows and observation retention.
const MaxWindow = 30 * 24 * time.Hour

// Validate checks the rule name, counting policy and enforcement.
func (r Rule) Validate() error {
	if r.Aggregation.Threshold <= 0 {
		return errors.New("threshold must be positive")
	}

	if !validRuleName(r.Name) {
		return errors.New("rule name must contain 1-64 bytes without whitespace or control characters")
	}
	if !validDuration(r.Aggregation.Window) || r.Aggregation.Window > MaxWindow {
		return errors.New("window must be at least one second in whole milliseconds and at most 30 days")
	}
	if r.Actions.Ban != 0 && (!validDuration(r.Actions.Ban) || r.Actions.Ban > bans.MaxDuration) {
		return errors.New("ban must be at least one second in whole milliseconds and at most 30 days")
	}
	if err := r.Aggregation.Validate(); err != nil {
		return err
	}
	if err := r.Selector.Validate(); err != nil {
		return err
	}

	return r.validateBan()
}

// validDuration checks the minimum and storage precision of a duration.
func validDuration(d time.Duration) bool {
	return d >= time.Second && d%time.Millisecond == 0
}

// Matches reports whether a normalized envelope satisfies the selectors and aggregation keys.
func (r Rule) Matches(e events.Envelope) bool {
	return r.Selector.Matches(e) && hasGroup(r.Aggregation.GroupBy, e) && hasGroup(r.Aggregation.Distinct, e)
}

// Matches checks event metadata independently of aggregation keys.
func (r Selector) Matches(e events.Envelope) bool {
	if e.Source != events.SourceKeycloak || e.Kind != r.Kind {
		return false
	}
	if !matchesSelector(r.Events, e.EventType()) {
		return false
	}
	if !matchesSelector(r.Operations, e.OperationType()) || !matchesSelector(r.Resources, e.ResourceType()) {
		return false
	}

	return !r.SuccessOnly || e.ErrorCode() == ""
}

// matchesSelector accepts any value when the selector is empty.
func matchesSelector(values []string, value string) bool {
	return len(values) == 0 || slices.Contains(values, value)
}

// RequiresIP reports whether the rule needs a valid address for counting.
func (r Aggregation) RequiresIP() bool {
	return r.GroupBy == GroupIP || r.Distinct == GroupIP
}

// Triggered reports whether the observed count satisfies the configured threshold.
func (r Rule) Triggered(count int) bool {
	return count >= r.Aggregation.Threshold
}

// Validate checks grouping and distinct keys.
func (r Aggregation) Validate() error {
	if r.GroupBy != GroupIP && r.GroupBy != GroupUser && r.GroupBy != GroupRealm {
		return errors.New("group-by must be ip, user-id or realm")
	}
	if r.Distinct != "" && r.Distinct != GroupIP && r.Distinct != GroupUser {
		return errors.New("distinct must be ip or user-id")
	}
	if r.Distinct == r.GroupBy {
		return errors.New("distinct must differ from group-by")
	}
	return nil
}

// Validate checks event and administrative filters.
func (r Selector) Validate() error {
	if !r.hasValidSelectors() {
		return errors.New("event, operation and resource selectors must be unique native uppercase identifiers")
	}
	switch r.Kind {
	case events.KindUser:
		if !r.hasUserTypes() {
			return errors.New("user rules require native user event selectors")
		}
		if len(r.Operations) != 0 || len(r.Resources) != 0 {
			return errors.New("operations and resources require kind: admin")
		}
	case events.KindAdmin:
		if len(r.Events) != 0 {
			return errors.New("admin rules must not specify user event selectors")
		}
	default:
		return errors.New("kind must be user or admin")
	}
	for _, operation := range r.Operations {
		if !events.ValidOperation(operation) {
			return fmt.Errorf("unsupported administrative operation %q", operation)
		}
	}
	return nil
}

// hasUserTypes checks the required native user event selectors.
func (r Selector) hasUserTypes() bool {
	if len(r.Events) == 0 {
		return false
	}
	for _, value := range r.Events {
		if !events.ValidUserType(value) {
			return false
		}
	}
	return true
}

// hasValidSelectors checks the configured selector lists.
func (r Selector) hasValidSelectors() bool {
	return validSelectors(r.Events) &&
		validSelectors(r.Operations) && validSelectors(r.Resources)
}

// validateBan ensures a ban rule identifies an unambiguous IP address.
func (r Rule) validateBan() error {
	if r.Actions.Ban == 0 {
		return nil
	}
	if r.Aggregation.GroupBy != GroupIP {
		return errors.New("ban actions require group-by: ip")
	}

	return nil
}

// validRuleName checks the length and characters of a rule name.
func validRuleName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}

	return !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

// validSelectors checks bounded, nonduplicated native identifiers.
func validSelectors(values []string) bool {
	if len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok || !events.ValidIdentifier(value) {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

// hasGroup checks whether the event can contribute to the aggregation key.
func hasGroup(group string, e events.Envelope) bool {
	switch group {
	case GroupIP:
		return e.IPAddress().IsValid()
	case GroupUser:
		return e.UserID() != "" && e.IdentityRealm() != ""
	case GroupRealm:
		return e.RealmID() != ""
	default:
		return group == ""
	}
}

// group returns the aggregation key and its optional identity realm.
func (r Aggregation) group(event events.Envelope) (key, realm string) {
	switch r.GroupBy {
	case GroupUser:
		return event.UserID(), event.IdentityRealm()
	case GroupRealm:
		return event.RealmID(), ""
	default:
		return event.Address(), ""
	}
}

// ValidateRules checks the complete detection policy.
func ValidateRules(rules []Rule) error {
	if len(rules) == 0 || len(rules) > 64 {
		return errors.New("configure between one and 64 rules")
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if _, ok := seen[rule.Name]; ok {
			return fmt.Errorf("duplicate rule %q", rule.Name)
		}
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		seen[rule.Name] = struct{}{}
	}
	return nil
}

// MatchQuery specifies the observations to count for a matching event.
type MatchQuery struct {
	// Source identifies the producer.
	Source string
	// Kind selects the event category.
	Kind string
	// Events selects native user event types.
	Events []string
	// Operations selects administrative operations.
	Operations []string
	// Resources selects administrative resource types.
	Resources []string
	// SuccessOnly excludes errors.
	SuccessOnly bool
	// GroupBy selects the aggregation key.
	GroupBy string
	// Key is the aggregation key value.
	Key string
	// IdentityRealm scopes user identifiers.
	IdentityRealm string
	// Distinct selects the optional distinct field.
	Distinct string
	// Since excludes observations at or before this time.
	Since time.Time
	// Through includes observations up to this time.
	Through time.Time
	// EligibleOnly excludes observations recorded while protected.
	EligibleOnly bool
	// CurrentGeneration restricts counting to the current ban generation.
	CurrentGeneration bool
	// ExcludeEventID omits the triggering event when evaluating a threshold crossing.
	ExcludeEventID string
}

// Query builds the counting criteria for a matching normalized envelope.
func (r Rule) Query(event events.Envelope, now time.Time) MatchQuery {
	key, realm := r.Aggregation.group(event)
	return MatchQuery{
		Source:            event.Source,
		Kind:              r.Selector.Kind,
		Events:            r.Selector.Events,
		Operations:        r.Selector.Operations,
		Resources:         r.Selector.Resources,
		SuccessOnly:       r.Selector.SuccessOnly,
		GroupBy:           r.Aggregation.GroupBy,
		Key:               key,
		IdentityRealm:     realm,
		Distinct:          r.Aggregation.Distinct,
		Since:             now.Add(-r.Aggregation.Window),
		Through:           now,
		EligibleOnly:      r.Actions.Ban > 0,
		CurrentGeneration: r.Actions.Ban > 0,
	}
}

// Rules maps stable names to detection policies as represented in YAML.
type Rules map[string]Rule

// Ordered returns a deterministic named policy snapshot.
func (rules Rules) Ordered() []Rule {
	ordered := make([]Rule, 0, len(rules))
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		rule := rules[name]
		rule.Name = name
		ordered = append(ordered, rule)
	}
	return ordered
}

// Validate checks every named rule.
func (rules Rules) Validate() error { return ValidateRules(rules.Ordered()) }

// RequiresEnforcement reports whether any rule requests automatic bans.
func (rules Rules) RequiresEnforcement() bool {
	for _, rule := range rules {
		if rule.Actions.Ban > 0 {
			return true
		}
	}
	return false
}
