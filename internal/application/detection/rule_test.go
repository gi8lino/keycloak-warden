package detection

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

func TestRuleValidate(t *testing.T) {
	t.Parallel()

	base := Rule{
		Name: "brute-force",
		Selector: Selector{
			Kind:   events.KindUser,
			Events: []string{events.TypeLoginError},
		},
		Aggregation: Aggregation{
			GroupBy:   GroupIP,
			Threshold: 1,
			Window:    time.Second,
		},
		Actions: Actions{
			Ban: time.Second,
		},
	}

	t.Run("accepts minimum values", func(t *testing.T) {
		t.Parallel()

		assert.NoError(t, base.Validate())
	})

	t.Run("rejects unnamed rule", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = ""

		assert.ErrorContains(t, rule.Validate(), "rule name")
	})

	t.Run("accepts uppercase and punctuation in rule names", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = "Auth/Login.Errors"

		assert.NoError(t, rule.Validate())
	})

	t.Run("accepts Unicode rule names", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = "Anmeldung/Fehlversuche-ä"

		assert.NoError(t, rule.Validate())
	})

	t.Run("accepts maximum rule name length", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = strings.Repeat("ä", 32)

		assert.NoError(t, rule.Validate())
	})

	t.Run("rejects oversized rule name", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = strings.Repeat("ä", 33)

		assert.ErrorContains(t, rule.Validate(), "rule name")
	})

	t.Run("rejects whitespace in rule name", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = "login errors"

		assert.ErrorContains(t, rule.Validate(), "rule name")
	})

	t.Run("rejects Unicode whitespace in rule name", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = "login\u00a0errors"

		assert.ErrorContains(t, rule.Validate(), "rule name")
	})

	t.Run("rejects control characters in rule name", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Name = "login\x00errors"

		assert.ErrorContains(t, rule.Validate(), "rule name")
	})

	t.Run("rejects malformed native event selector", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Selector.Events = []string{"Login_ERROR"}

		assert.ErrorContains(t, rule.Validate(), "uppercase identifiers")
	})

	t.Run("rejects malformed resource selector", func(t *testing.T) {
		t.Parallel()

		selector := Selector{
			Kind:      events.KindAdmin,
			Resources: []string{"USER-ROLE"},
		}

		assert.ErrorContains(t, selector.Validate(), "uppercase identifiers")
	})

	t.Run("rejects missing events", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Selector.Events = nil

		assert.ErrorContains(t, rule.Validate(), "selectors")
	})

	t.Run("rejects administrative selectors on user rules", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Selector.Operations = []string{"CREATE"}

		assert.ErrorContains(t, rule.Validate(), "kind: admin")
	})

	t.Run("rejects synthetic admin user event type", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Selector.Events = []string{"ADMIN"}

		assert.ErrorContains(t, rule.Validate(), "native user event selectors")
	})

	t.Run("rejects missing aggregation key", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Aggregation.GroupBy = ""

		assert.ErrorContains(t, rule.Validate(), "group-by")
	})

	t.Run("rejects zero threshold", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Aggregation.Threshold = 0

		assert.EqualError(t, rule.Validate(), "threshold must be positive")
	})

	t.Run("rejects negative threshold", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Aggregation.Threshold = -1

		assert.EqualError(t, rule.Validate(), "threshold must be positive")
	})

	t.Run("rejects short window", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Aggregation.Window = time.Second - 1

		assert.ErrorContains(t, rule.Validate(), "window must be at least one second")
	})

	t.Run("rejects short ban", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Actions.Ban = time.Second - 1

		assert.ErrorContains(t, rule.Validate(), "ban must be at least one second")
	})

	t.Run("accepts bans for successful user events", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Selector.Events = []string{"LOGIN"}
		rule.Selector.SuccessOnly = true

		assert.NoError(t, rule.Validate())
	})

	t.Run("accepts bans for mixed user event types", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Selector.Events = []string{"LOGIN", events.TypeLoginError}

		assert.NoError(t, rule.Validate())
	})

	t.Run("rejects bans grouped by user", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Aggregation.GroupBy = GroupUser

		assert.ErrorContains(t, rule.Validate(), "group-by: ip")
	})

	t.Run("rejects bans grouped by realm", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Aggregation.GroupBy = GroupRealm

		assert.ErrorContains(t, rule.Validate(), "group-by: ip")
	})

	t.Run("accepts recording without a ban", func(t *testing.T) {
		t.Parallel()

		rule := base
		rule.Actions.Ban = 0

		assert.NoError(t, rule.Validate())
	})
}

func TestValidDuration(t *testing.T) {
	t.Parallel()

	t.Run("minimum", func(t *testing.T) {
		t.Parallel()

		assert.True(t, validDuration(time.Second))
	})

	t.Run("too short", func(t *testing.T) {
		t.Parallel()

		assert.False(t, validDuration(time.Millisecond))
	})

	t.Run("fractional millisecond", func(t *testing.T) {
		t.Parallel()

		assert.False(t, validDuration(time.Second+time.Microsecond))
	})
}

func TestRuleMatches(t *testing.T) {
	t.Parallel()

	rule := Rule{
		Name: "brute-force",
		Selector: Selector{
			Kind:   events.KindUser,
			Events: []string{events.TypeLoginError},
		},
		Aggregation: Aggregation{
			GroupBy: GroupIP,
		},
	}

	valid := events.Envelope{
		Version: events.SchemaVersion,
		Source:  events.SourceKeycloak,
		Kind:    events.KindUser,
		User: &events.UserEvent{
			Type: events.TypeLoginError,
			IP:   "203.0.113.1",
		},
	}

	t.Run("matches Keycloak login failure with IP", func(t *testing.T) {
		t.Parallel()

		assert.True(t, rule.Matches(valid))
	})

	t.Run("ignores success", func(t *testing.T) {
		t.Parallel()

		event := valid
		body := *valid.User
		body.Type = "LOGIN"
		event.User = &body

		assert.False(t, rule.Matches(event))
	})

	t.Run("ignores other source", func(t *testing.T) {
		t.Parallel()

		event := valid
		event.Source = "other"

		assert.False(t, rule.Matches(event))
	})

	t.Run("ignores missing IP", func(t *testing.T) {
		t.Parallel()

		event := valid
		body := *valid.User
		body.IP = ""
		event.User = &body

		assert.False(t, rule.Matches(event))
	})
}

func TestRuleTriggered(t *testing.T) {
	t.Parallel()

	t.Run("below threshold", func(t *testing.T) {
		t.Parallel()

		rule := Rule{Aggregation: Aggregation{Threshold: 5}}

		assert.False(t, rule.Triggered(4))
	})

	t.Run("at threshold", func(t *testing.T) {
		t.Parallel()

		rule := Rule{Aggregation: Aggregation{Threshold: 5}}

		assert.True(t, rule.Triggered(5))
	})

	t.Run("above threshold", func(t *testing.T) {
		t.Parallel()

		rule := Rule{Aggregation: Aggregation{Threshold: 5}}

		assert.True(t, rule.Triggered(6))
	})
}

func TestNamedRule(t *testing.T) {
	t.Parallel()

	admin := Rule{
		Name: "role-changes",
		Selector: Selector{
			Kind:        events.KindAdmin,
			Operations:  []string{"CREATE"},
			Resources:   []string{"REALM_ROLE_MAPPING"},
			SuccessOnly: true,
		},
		Aggregation: Aggregation{
			GroupBy:   GroupRealm,
			Threshold: 1,
			Window:    time.Minute,
		},
	}
	event := events.Envelope{
		Version: events.SchemaVersion,
		Source:  events.SourceKeycloak,
		Kind:    events.KindAdmin,
		Admin: &events.AdminEvent{
			RealmID:       "target",
			OperationType: "CREATE",
			ResourceType:  "REALM_ROLE_MAPPING",
			Actor: &events.Actor{
				RealmID: "master",
				UserID:  "administrator",
			},
		},
	}

	t.Run("matches admin change without IP", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, admin.Validate())
		assert.True(t, admin.Matches(event))
	})

	t.Run("excludes failed administrative changes", func(t *testing.T) {
		t.Parallel()

		failed := event
		body := *event.Admin
		body.Error = "forbidden"
		failed.Admin = &body

		assert.False(t, admin.Matches(failed), "failed admin event matched success-only rule")
	})

	t.Run("accepts administrative IP bans", func(t *testing.T) {
		t.Parallel()

		rule := admin
		rule.Aggregation.GroupBy = GroupIP
		rule.Actions.Ban = time.Minute

		require.NoError(t, rule.Validate())

		input := event
		body := *event.Admin
		actor := *body.Actor
		actor.IP = "203.0.113.1"
		body.Actor = &actor
		input.Admin = &body

		assert.True(t, rule.Matches(input))

		query := rule.Query(input, time.Now())
		assert.Equal(t, actor.IP, query.Key)
		assert.Equal(t, events.KindAdmin, query.Kind)
		assert.True(t, query.SuccessOnly)
		assert.True(t, query.EligibleOnly)
		assert.True(t, query.CurrentGeneration)
	})

	t.Run("admin bans require a source IP", func(t *testing.T) {
		t.Parallel()

		rule := admin
		rule.Aggregation.GroupBy = GroupIP
		rule.Actions.Ban = time.Minute

		require.NoError(t, rule.Validate())
		assert.False(t, rule.Matches(event))

		input := event
		body := *event.Admin
		body.Actor = nil
		input.Admin = &body

		assert.False(t, rule.Matches(input))
	})

	t.Run("rejects administrative realm bans", func(t *testing.T) {
		t.Parallel()

		rule := admin
		rule.Actions.Ban = time.Minute

		assert.ErrorContains(t, rule.Validate(), "group-by: ip")
	})

	t.Run("does not count missing user identity for spraying", func(t *testing.T) {
		t.Parallel()

		rule := Rule{
			Name: "spraying",
			Selector: Selector{
				Kind:   events.KindUser,
				Events: []string{events.TypeLoginError},
			},
			Aggregation: Aggregation{
				GroupBy:   GroupIP,
				Distinct:  GroupUser,
				Threshold: 3,
				Window:    time.Minute,
			},
			Actions: Actions{
				Ban: time.Hour,
			},
		}
		input := events.Envelope{
			Version: events.SchemaVersion,
			Source:  events.SourceKeycloak,
			Kind:    events.KindUser,
			User: &events.UserEvent{
				Type:    events.TypeLoginError,
				RealmID: "hq",
				IP:      "203.0.113.1",
			},
		}

		require.NoError(t, rule.Validate())
		assert.False(t, rule.Matches(input))

		input.User.UserID = "user-a"
		assert.True(t, rule.Matches(input))
	})

	t.Run("rejects user selectors on admin rules", func(t *testing.T) {
		t.Parallel()

		rule := admin
		rule.Selector.Events = []string{events.TypeLoginError}

		assert.ErrorContains(t, rule.Validate(), "admin rules")
	})

	t.Run("rejects missing rule kind", func(t *testing.T) {
		t.Parallel()

		rule := admin
		rule.Selector.Kind = ""

		assert.ErrorContains(t, rule.Validate(), "kind must be user or admin")
	})

	t.Run("admin without selectors matches only admin events", func(t *testing.T) {
		t.Parallel()

		rule := admin
		rule.Selector.Operations = nil
		rule.Selector.Resources = nil

		require.NoError(t, rule.Validate())
		assert.True(t, rule.Matches(event))

		user := events.Envelope{
			Version: events.SchemaVersion,
			Source:  events.SourceKeycloak,
			Kind:    events.KindUser,
			User: &events.UserEvent{
				Type:    events.TypeLoginError,
				RealmID: "target",
			},
		}

		assert.False(t, rule.Matches(user))
	})

	t.Run("rejects duplicate rule names", func(t *testing.T) {
		t.Parallel()

		assert.ErrorContains(t, ValidateRules([]Rule{admin, admin}), "duplicate rule")
	})
}
