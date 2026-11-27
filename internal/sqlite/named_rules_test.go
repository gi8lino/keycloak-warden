package sqlite

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// namedLogin creates a user event with a stable identity and address.
func namedLogin(t *testing.T, id, realm, user, ip string, at time.Time) events.Envelope {
	t.Helper()
	return events.Envelope{
		Version:   events.SchemaVersion,
		ID:        id,
		Source:    events.SourceKeycloak,
		Kind:      events.KindUser,
		Timestamp: at,
		User: &events.UserEvent{
			Type:    events.TypeLoginError,
			RealmID: realm,
			UserID:  user,
			IP:      ip,
		},
	}
}

// ipRule constructs a named failed-login rule.
func ipRule(t *testing.T, name string, threshold int, ban time.Duration) detection.Rule {
	t.Helper()
	return detection.Rule{
		Name: name,
		Selector: detection.Selector{
			Kind:   events.KindUser,
			Events: []string{events.TypeLoginError},
		},
		Aggregation: detection.Aggregation{
			GroupBy:   detection.GroupIP,
			Threshold: threshold,
			Window:    time.Minute,
		},
		Actions: detection.Actions{
			Ban: ban,
		},
	}
}

func TestNamedRules(t *testing.T) {
	t.Parallel()

	t.Run("overlapping bans produce one revision and preserve longest expiry", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		service, err := ingestion.New(store, []detection.Rule{
			ipRule(t, "short", 2, time.Minute),
			ipRule(t, "long", 2, time.Hour),
		}, []string{"edge"}, bans.Policy{})
		require.NoError(t, err)

		first := namedLogin(t, "first", "hq", "one", "203.0.113.1", now)
		result, err := service.Process(t.Context(), first, func() time.Time { return now })
		require.NoError(t, err)
		assert.Nil(t, result.Decision)

		result, err = service.Process(t.Context(), first, func() time.Time { return now })
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeDuplicate, result.Outcome)
		assert.Empty(t, result.Incidents)

		second := namedLogin(t, "second", "hq", "two", first.User.IP, now)
		result, err = service.Process(t.Context(), second, func() time.Time { return now })
		require.NoError(t, err)
		require.NotNil(t, result.Decision)
		assert.EqualValues(t, 1, result.Decision.Revision)
		assert.Equal(t, now.Add(time.Hour), result.Decision.ExpiresAt)
		require.Len(t, result.Incidents, 2)
		assert.Equal(t, "long", result.Incidents[0].Rule)
		assert.Positive(t, result.Incidents[0].ID)

		result, err = service.Process(t.Context(), second, func() time.Time { return now })
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeDuplicate, result.Outcome)
		assert.Empty(t, result.Incidents)
		page, err := store.Incidents(t.Context(), overview.IncidentQuery{})
		require.NoError(t, err)
		require.Len(t, page.Items, 2)
	})

	t.Run("counts distinct realm-scoped users instead of repeated failures", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		rule := ipRule(t, "spraying", 2, time.Hour)
		rule.Aggregation.Distinct = detection.GroupUser
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{})
		require.NoError(t, err)

		first := namedLogin(t, "one", "hq", "user", "203.0.113.1", now)
		result, err := service.Process(t.Context(), first, func() time.Time { return now })
		require.NoError(t, err)
		assert.Equal(t, 1, result.Evaluations[0].Count)
		second := first
		second.ID = "two"
		result, err = service.Process(t.Context(), second, func() time.Time { return now })
		require.NoError(t, err)
		assert.Equal(t, 1, result.Evaluations[0].Count)
		assert.Nil(t, result.Decision)
		third := namedLogin(t, "three", "another", "user", first.User.IP, now)
		result, err = service.Process(t.Context(), third, func() time.Time { return now })
		require.NoError(t, err)
		require.NotNil(t, result.Decision)
		assert.Equal(t, 2, result.Evaluations[0].Count)
	})

	t.Run("distributed attempts are grouped by realm and user", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		rule := ipRule(t, "distributed", 2, 0)
		rule.Aggregation.GroupBy = detection.GroupUser
		rule.Aggregation.Distinct = detection.GroupIP
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{})
		require.NoError(t, err)

		first := namedLogin(t, "one", "hq", "user", "203.0.113.1", now)
		result, err := service.Process(t.Context(), first, func() time.Time { return now })
		require.NoError(t, err)
		assert.Empty(t, result.Incidents)
		other := namedLogin(t, "two", "other-realm", "user", "203.0.113.2", now)
		result, err = service.Process(t.Context(), other, func() time.Time { return now })
		require.NoError(t, err)
		assert.Empty(t, result.Incidents)
		third := namedLogin(t, "three", "hq", "user", "203.0.113.3", now)
		result, err = service.Process(t.Context(), third, func() time.Time { return now })
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, ingestion.OutcomeIncident, result.Outcome)
		assert.Nil(t, result.Decision)
		assert.Equal(t, 2, result.Incidents[0].Count)
	})

	t.Run("admin metadata cannot contribute to login bans", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		service, err := ingestion.New(store, []detection.Rule{
			ipRule(t, "brute-force", 2, time.Hour),
			{
				Name: "admin-user-create",
				Selector: detection.Selector{
					Kind:        events.KindAdmin,
					Operations:  []string{"CREATE"},
					Resources:   []string{"USER"},
					SuccessOnly: true,
				},
				Aggregation: detection.Aggregation{
					GroupBy:   detection.GroupRealm,
					Threshold: 1,
					Window:    time.Minute,
				},
			},
		}, nil, bans.Policy{})
		require.NoError(t, err)

		admin := events.Envelope{
			Version:   events.SchemaVersion,
			ID:        "admin",
			Source:    events.SourceKeycloak,
			Kind:      events.KindAdmin,
			Timestamp: now,
			Admin: &events.AdminEvent{
				RealmID:       "hq",
				OperationType: "CREATE",
				ResourceType:  "USER",
				ResourcePath:  "users/created-user",
				Actor: &events.Actor{
					RealmID: "master",
					UserID:  "actor",
					IP:      "203.0.113.1",
				},
			},
		}
		result, err := service.Process(t.Context(), admin, func() time.Time { return now })
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, "master", result.Incidents[0].ActorRealmID)
		assert.Nil(t, result.Decision)
		result, err = service.Process(t.Context(), namedLogin(t, "login", "hq", "user", admin.Admin.Actor.IP, now), func() time.Time { return now })
		require.NoError(t, err)
		assert.Equal(t, 1, result.Evaluations[0].Count)
		assert.Nil(t, result.Decision)
	})

	t.Run("separates category counts for the same IP without admin selectors", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		adminRule := detection.Rule{
			Name: "admin-activity",
			Selector: detection.Selector{
				Kind: events.KindAdmin,
			},
			Aggregation: detection.Aggregation{
				GroupBy:   detection.GroupIP,
				Threshold: 2,
				Window:    time.Minute,
			},
		}
		service, err := ingestion.New(store, []detection.Rule{ipRule(t, "user-activity", 2, 0), adminRule}, nil, bans.Policy{})
		require.NoError(t, err)
		const ip = "203.0.113.1"
		result, err := service.Process(t.Context(), namedLogin(t, "user-1", "hq", "user", ip, now), func() time.Time { return now })
		require.NoError(t, err)
		assert.Empty(t, result.Incidents)
		admin := events.Envelope{
			Version:   events.SchemaVersion,
			ID:        "admin-1",
			Source:    events.SourceKeycloak,
			Kind:      events.KindAdmin,
			Timestamp: now,
			Admin: &events.AdminEvent{
				RealmID:       "hq",
				OperationType: "UPDATE",
				ResourceType:  "USER",
				Actor: &events.Actor{
					RealmID: "master",
					UserID:  "administrator",
					IP:      ip,
				},
			},
		}
		result, err = service.Process(t.Context(), admin, func() time.Time { return now })
		require.NoError(t, err)
		assert.Empty(t, result.Incidents)
		admin.ID = "admin-2"
		result, err = service.Process(t.Context(), admin, func() time.Time { return now })
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, events.KindAdmin, result.Incidents[0].EventKind)
		assert.Equal(t, 2, result.Incidents[0].Count)
		result, err = service.Process(t.Context(), namedLogin(t, "user-2", "hq", "user", ip, now), func() time.Time { return now })
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, events.KindUser, result.Incidents[0].EventKind)
		assert.Equal(t, 2, result.Incidents[0].Count)
	})

	t.Run("protected records remain ineligible for later bans", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		rules := []detection.Rule{ipRule(t, "ban", 2, time.Hour), ipRule(t, "record", 1, 0)}
		protection, err := bans.NewProtection([]string{"203.0.113.1"})
		require.NoError(t, err)
		service, err := ingestion.New(store, rules, nil, bans.Policy{Protection: protection})
		require.NoError(t, err)
		result, err := service.Process(t.Context(), namedLogin(t, "protected", "hq", "user", "203.0.113.1", now), func() time.Time { return now })
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		assert.Nil(t, result.Decision)

		service, err = ingestion.New(store, rules, nil, bans.Policy{})
		require.NoError(t, err)
		result, err = service.Process(t.Context(), namedLogin(t, "new", "hq", "user", "203.0.113.1", now), func() time.Time { return now })
		require.NoError(t, err)
		assert.Nil(t, result.Decision)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, "record", result.Incidents[0].Rule)
	})

	t.Run("observe-only records incident and hypothetical ban without decision", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		service, err := ingestion.New(store, []detection.Rule{ipRule(t, "ban", 1, time.Hour)}, nil, bans.Policy{ObserveOnly: true})
		require.NoError(t, err)
		result, err := service.Process(t.Context(), namedLogin(t, "one", "hq", "user", "203.0.113.1", now), func() time.Time { return now })
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeObserved, result.Outcome)
		assert.Nil(t, result.Decision)
		require.Len(t, result.Incidents, 1)
		assert.True(t, result.Incidents[0].ObserveOnly)
		require.NotNil(t, result.Incidents[0].BanUntil)
		assert.Equal(t, now.Add(time.Hour), *result.Incidents[0].BanUntil)
		page, err := store.Incidents(t.Context(), overview.IncidentQuery{})
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		assert.True(t, page.Items[0].ObserveOnly)
		require.NotNil(t, page.Items[0].BanUntil)
		assert.Equal(t, now.Add(time.Hour), *page.Items[0].BanUntil)
	})

	t.Run("failed reconciliation rolls back receipt and incident", func(t *testing.T) {
		t.Parallel()
		store := openAtomicityStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		service, err := ingestion.New(store, []detection.Rule{ipRule(t, "ban", 1, time.Hour)}, []string{"edge"}, bans.Policy{})
		require.NoError(t, err)
		_, err = store.db.Exec(`
CREATE TRIGGER reject_rule_reconciliation BEFORE UPDATE OF revision ON decisions
BEGIN
    SELECT RAISE(ABORT, 'rule reconciliation failed');
END
`)
		require.NoError(t, err)
		event := namedLogin(t, "one", "hq", "user", "203.0.113.1", now)
		result, err := service.Process(t.Context(), event, func() time.Time { return now })
		require.ErrorContains(t, err, "rule reconciliation failed")
		assert.Empty(t, result.Incidents)
		var count int
		require.NoError(t, store.db.QueryRow(`SELECT COUNT(*) FROM event_observations`).Scan(&count))
		assert.Zero(t, count)
		require.NoError(t, store.db.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&count))
		assert.Zero(t, count)
		select {
		case <-store.Changes():
			t.Fatal("rollback notified worker")
		default:
		}
		_, err = store.db.Exec(`DROP TRIGGER reject_rule_reconciliation`)
		require.NoError(t, err)
		result, err = service.Process(t.Context(), event, func() time.Time { return now })
		require.NoError(t, err)
		require.NotNil(t, result.Decision)
		assert.Equal(t, model.DecisionBanned, result.Decision.State)
	})
}

func TestEventBanPolicy(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Millisecond)
	clock := func() time.Time { return now }
	const ip = "203.0.113.1"
	admin := events.Envelope{
		Version:   events.SchemaVersion,
		ID:        "admin",
		Source:    events.SourceKeycloak,
		Kind:      events.KindAdmin,
		Timestamp: now,
		Admin: &events.AdminEvent{
			RealmID:       "hq",
			OperationType: "CREATE",
			ResourceType:  "USER",
			ResourcePath:  "users/new-user",
			Actor: &events.Actor{
				RealmID: "master",
				UserID:  "administrator",
				IP:      ip,
			},
		},
	}
	rule := detection.Rule{
		Name: "admin-ban",
		Selector: detection.Selector{
			Kind:        events.KindAdmin,
			Operations:  []string{"CREATE"},
			Resources:   []string{"USER"},
			SuccessOnly: true,
		},
		Aggregation: detection.Aggregation{
			GroupBy:   detection.GroupIP,
			Threshold: 1,
			Window:    time.Minute,
		},
		Actions: detection.Actions{
			Ban: time.Minute,
		},
	}

	t.Run("bans successful user events", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		loginRule := ipRule(t, "login-rate", 1, time.Minute)
		loginRule.Selector.Events = []string{"LOGIN"}
		loginRule.Selector.SuccessOnly = true
		service, err := ingestion.New(store, []detection.Rule{loginRule}, []string{"edge"}, bans.Policy{})
		require.NoError(t, err)

		event := namedLogin(t, "login", "hq", "user", ip, now)
		event.User.Type = "LOGIN"
		result, err := service.Process(t.Context(), event, clock)

		require.NoError(t, err)
		require.NotNil(t, result.Decision)
		assert.Equal(t, model.DecisionBanned, result.Decision.State)
		assert.Equal(t, ip, result.Decision.IP)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, "LOGIN", result.Incidents[0].EventType)
	})

	t.Run("bans the administrative actor IP", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		service, err := ingestion.New(store, []detection.Rule{rule}, []string{"edge"}, bans.Policy{})
		require.NoError(t, err)

		result, err := service.Process(t.Context(), admin, clock)

		require.NoError(t, err)
		require.NotNil(t, result.Decision)
		assert.Equal(t, model.DecisionBanned, result.Decision.State)
		assert.Equal(t, ip, result.Decision.IP)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, events.KindAdmin, result.Incidents[0].EventKind)
		assert.Equal(t, "master", result.Incidents[0].ActorRealmID)
	})

	t.Run("excludes protected administrative actor IPs", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		protection, err := bans.NewProtection([]string{ip})
		require.NoError(t, err)
		service, err := ingestion.New(store, []detection.Rule{rule}, []string{"edge"}, bans.Policy{
			Protection: protection,
		})
		require.NoError(t, err)

		result, err := service.Process(t.Context(), admin, clock)

		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeProtected, result.Outcome)
		assert.Nil(t, result.Decision)
		assert.Empty(t, result.Incidents)
	})

	t.Run("observes administrative bans without enforcement", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{
			ObserveOnly: true,
		})
		require.NoError(t, err)

		result, err := service.Process(t.Context(), admin, clock)

		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeObserved, result.Outcome)
		assert.Nil(t, result.Decision)
		require.Len(t, result.Incidents, 1)
		assert.True(t, result.Incidents[0].ObserveOnly)
		require.NotNil(t, result.Incidents[0].BanUntil)
		assert.Equal(t, now.Add(time.Minute), *result.Incidents[0].BanUntil)
	})
}

func TestIncidentReferencesExistingDecision(t *testing.T) {
	t.Parallel()

	store := openAtomicityStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	ip := "203.0.113.1"
	existing, err := bans.ApplyManualBan(ctx, store, ip, now.Add(time.Hour), "manual", now, []string{"edge"})
	require.NoError(t, err)
	service, err := ingestion.New(store, []detection.Rule{ipRule(t, "short", 1, time.Minute)}, []string{"edge"}, bans.Policy{})
	require.NoError(t, err)

	result, err := service.Process(ctx, namedLogin(t, "one", "hq", "user", ip, now), func() time.Time { return now })
	require.NoError(t, err)
	assert.Equal(t, ingestion.OutcomeUnchanged, result.Outcome)
	assert.Nil(t, result.Decision, "an unchanged decision must not count as a new revision")
	require.Len(t, result.Incidents, 1)
	assert.Equal(t, existing.Decision.ID, result.Incidents[0].DecisionID)
	assert.Equal(t, existing.Decision.Revision, result.Incidents[0].DecisionRevision)

	page, err := store.Incidents(ctx, overview.IncidentQuery{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, existing.Decision.ID, page.Items[0].DecisionID)
	assert.Equal(t, existing.Decision.Revision, page.Items[0].DecisionRevision)
}
