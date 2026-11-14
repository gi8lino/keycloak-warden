package bans

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// policyTx captures storage primitives requested by the domain reconciliation.
type policyTx struct {
	// prior is the materialized state before reconciliation.
	prior          decisions.Decision
	currentSources []Source
	// oldSource is the previous source when one exists.
	oldSource Source
	// oldSourceExists indicates an existing source renewal.
	oldSourceExists bool
	// written is the source supplied by the application.
	written Source
	// ensured records whether an identity was requested.
	ensured bool
	// saved records the reconciled decision.
	saved decisions.Decision
	// savedChanged records whether persistence was asked to revise state.
	savedChanged bool
	// savedTargets are destination identifiers supplied for delivery.
	savedTargets []string
}

func (p *policyTx) EnsureDecision(context.Context, string) error {
	p.ensured = true
	return nil
}

func (p *policyTx) Source(context.Context, string, SourceKind) (Source, bool, error) {
	return p.oldSource, p.oldSourceExists, nil
}

func (p *policyTx) PutSource(_ context.Context, _ string, source Source) error {
	p.written = source
	p.currentSources = []Source{source}
	return nil
}

func (p *policyTx) Decision(context.Context, string) (decisions.Decision, error) {
	return p.prior, nil
}

func (p *policyTx) Sources(context.Context, string, time.Time) ([]Source, error) {
	return p.currentSources, nil
}

func (p *policyTx) SaveDecision(_ context.Context, _, next decisions.Decision, changed bool, targets []string) error {
	p.saved = next
	p.savedChanged = changed
	p.savedTargets = append([]string(nil), targets...)
	return nil
}

func TestExtendSource(t *testing.T) {
	t.Parallel()

	t.Run("keeps a longer existing expiry", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		tx := &policyTx{
			oldSource:       Source{Kind: SourceManual, ExpiresAt: now.Add(time.Hour)},
			oldSourceExists: true,
		}
		err := ExtendSource(t.Context(), tx, "203.0.113.1", Source{
			Kind: SourceManual, ExpiresAt: now.Add(time.Minute), Reason: "renewal",
		})

		require.NoError(t, err)
		assert.True(t, tx.ensured)
		assert.Equal(t, now.Add(time.Hour), tx.written.ExpiresAt)
		assert.Equal(t, "renewal", tx.written.Reason)
	})

	t.Run("accepts a new source expiry", func(t *testing.T) {
		t.Parallel()

		until := time.Now().Add(time.Hour)
		tx := &policyTx{}
		err := ExtendSource(t.Context(), tx, "203.0.113.2", Source{
			Kind: SourceAutomatic, ExpiresAt: until,
		})

		require.NoError(t, err)
		assert.True(t, tx.ensured)
		assert.Equal(t, until, tx.written.ExpiresAt)
	})
}

func TestReconcileDecisionTransaction(t *testing.T) {
	t.Parallel()

	t.Run("revises the decision and passes destinations to storage", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		previous := decisions.Decision{ID: "id", IP: "203.0.113.3", State: decisions.StateUnbanned, Revision: 1}
		tx := &policyTx{
			prior:          previous,
			currentSources: []Source{{Kind: SourceManual, ExpiresAt: now.Add(time.Hour)}},
		}
		next, changed, err := ReconcileDecision(t.Context(), tx, previous.IP, now, []string{"cloudflare.edge"})

		require.NoError(t, err)
		assert.True(t, changed)
		assert.EqualValues(t, 2, next.Revision)
		assert.Equal(t, decisions.StateBanned, next.State)
		assert.Equal(t, next, tx.saved)
		assert.Equal(t, []string{"cloudflare.edge"}, tx.savedTargets)
	})

	t.Run("does not change revision when effective policy is unchanged", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		previous := decisions.Decision{
			ID: "id", IP: "203.0.113.4", State: decisions.StateBanned,
			Revision: 4, ExpiresAt: now.Add(time.Hour),
		}
		tx := &policyTx{
			prior:          previous,
			currentSources: []Source{{Kind: SourceManual, ExpiresAt: previous.ExpiresAt}},
		}
		next, changed, err := ReconcileDecision(t.Context(), tx, previous.IP, now, nil)

		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, previous, next)
		assert.False(t, tx.savedChanged)
	})
}
