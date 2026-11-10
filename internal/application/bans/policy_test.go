package bans_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestExtendExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, now.Add(time.Hour), bans.ExtendExpiry(now.Add(time.Hour), now.Add(time.Minute)))
	assert.Equal(t, now.Add(time.Hour), bans.ExtendExpiry(now.Add(time.Minute), now.Add(time.Hour)))
}

func TestReconcile(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	prior := decisions.Decision{
		ID: "stable", IP: "203.0.113.10", Revision: 3,
		State: decisions.StateBanned, ExpiresAt: now.Add(time.Hour),
	}

	t.Run("identical desired state does not create a revision", func(t *testing.T) {
		t.Parallel()
		next, changed := bans.Reconcile(prior, []bans.Source{
			{Kind: bans.SourceManual, ExpiresAt: now.Add(time.Hour)},
			{Kind: bans.SourceAutomatic, ExpiresAt: now.Add(10 * time.Minute)},
		}, now)
		assert.False(t, changed)
		assert.Equal(t, prior, next)
	})

	t.Run("expired source cannot shorten active ban", func(t *testing.T) {
		t.Parallel()
		next, changed := bans.Reconcile(prior, []bans.Source{
			{Kind: bans.SourceManual, ExpiresAt: now.Add(time.Hour)},
			{Kind: bans.SourceAutomatic, ExpiresAt: now.Add(-time.Minute)},
		}, now)
		assert.False(t, changed)
		assert.Equal(t, prior, next)
	})

	t.Run("longer source extends expiry once", func(t *testing.T) {
		t.Parallel()
		next, changed := bans.Reconcile(prior, []bans.Source{{ExpiresAt: now.Add(2 * time.Hour)}}, now)
		assert.True(t, changed)
		assert.Equal(t, prior.Revision+1, next.Revision)
		assert.Equal(t, now.Add(2*time.Hour), next.ExpiresAt)
		assert.Equal(t, decisions.StateBanned, next.State)
	})

	t.Run("last source expiry releases without losing historical expiry", func(t *testing.T) {
		t.Parallel()
		next, changed := bans.Reconcile(prior, []bans.Source{{ExpiresAt: now.Add(-time.Minute)}}, now)
		assert.True(t, changed)
		assert.Equal(t, prior.Revision+1, next.Revision)
		assert.Equal(t, decisions.StateUnbanned, next.State)
		assert.Equal(t, prior.ExpiresAt, next.ExpiresAt)
		released, again := bans.Reconcile(next, nil, now)
		assert.False(t, again)
		assert.Equal(t, next, released)
	})

	t.Run("source reason does not change delivered decision", func(t *testing.T) {
		t.Parallel()
		next, changed := bans.Reconcile(prior, []bans.Source{{Kind: bans.SourceManual, ExpiresAt: now.Add(time.Hour), Reason: "different"}}, now)
		assert.False(t, changed)
		assert.Equal(t, prior, next)
	})

}
