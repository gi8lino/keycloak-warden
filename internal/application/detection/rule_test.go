package detection

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/events"
)

func TestRuleValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts minimum values", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, (Rule{
			Threshold: 1,
			Window:    time.Second,
			Ban:       time.Second,
		}).Validate())
	})

	t.Run("rejects zero threshold", func(t *testing.T) {
		t.Parallel()

		require.EqualError(t, (Rule{Window: time.Second, Ban: time.Second}).Validate(), "threshold must be positive")
	})

	t.Run("rejects negative threshold", func(t *testing.T) {
		t.Parallel()

		require.EqualError(
			t,
			(Rule{
				Threshold: -1,
				Window:    time.Second,
				Ban:       time.Second,
			}).Validate(),
			"threshold must be positive",
		)
	})

	t.Run("rejects short window", func(t *testing.T) {
		t.Parallel()

		require.EqualError(
			t,
			(Rule{
				Threshold: 1,
				Window:    time.Second - 1,
				Ban:       time.Second,
			}).Validate(),
			"window and ban must be at least one second",
		)
	})

	t.Run("rejects short ban", func(t *testing.T) {
		t.Parallel()

		require.EqualError(
			t,
			(Rule{
				Threshold: 1,
				Window:    time.Second,
				Ban:       time.Second - 1,
			}).Validate(),
			"window and ban must be at least one second",
		)
	})
}

func TestRuleHasValidThreshold(t *testing.T) {
	t.Parallel()

	t.Run("positive", func(t *testing.T) {
		t.Parallel()

		assert.True(t, (Rule{Threshold: 1}).hasValidThreshold())
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()

		assert.False(t, (Rule{}).hasValidThreshold())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()

		assert.False(t, (Rule{Threshold: -1}).hasValidThreshold())
	})
}

func TestRuleHasValidDurations(t *testing.T) {
	t.Parallel()

	t.Run("minimum", func(t *testing.T) {
		t.Parallel()

		assert.True(t, (Rule{Window: time.Second, Ban: time.Second}).hasValidDurations())
	})

	t.Run("window too short", func(t *testing.T) {
		t.Parallel()

		assert.False(t, (Rule{Window: time.Millisecond, Ban: time.Second}).hasValidDurations())
	})

	t.Run("ban too short", func(t *testing.T) {
		t.Parallel()

		assert.False(t, (Rule{Window: time.Second, Ban: time.Millisecond}).hasValidDurations())
	})
}

func TestRuleMatches(t *testing.T) {
	t.Parallel()

	valid := events.Event{
		Source: "keycloak",
		Kind:   "LOGIN_ERROR",
		IP:     netip.MustParseAddr("203.0.113.1"),
	}

	t.Run("matches Keycloak login failure with IP", func(t *testing.T) {
		t.Parallel()

		assert.True(t, (Rule{}).Matches(valid))
	})

	t.Run("ignores success", func(t *testing.T) {
		t.Parallel()

		event := valid
		event.Kind = "LOGIN"

		assert.False(t, (Rule{}).Matches(event))
	})

	t.Run("ignores other source", func(t *testing.T) {
		t.Parallel()

		event := valid
		event.Source = "other"

		assert.False(t, (Rule{}).Matches(event))
	})

	t.Run("ignores missing IP", func(t *testing.T) {
		t.Parallel()

		event := valid
		event.IP = netip.Addr{}

		assert.False(t, (Rule{}).Matches(event))
	})
}

func TestRuleTriggered(t *testing.T) {
	t.Parallel()

	t.Run("below threshold", func(t *testing.T) {
		t.Parallel()

		assert.False(t, (Rule{Threshold: 5}).Triggered(4))
	})

	t.Run("at threshold", func(t *testing.T) {
		t.Parallel()

		assert.True(t, (Rule{Threshold: 5}).Triggered(5))
	})

	t.Run("above threshold", func(t *testing.T) {
		t.Parallel()

		assert.True(t, (Rule{Threshold: 5}).Triggered(6))
	})
}
