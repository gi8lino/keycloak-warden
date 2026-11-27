package bans

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// policyTx captures storage primitives requested by the domain reconciliation.
type policyTx struct {
	// prior is the materialized state before reconciliation.
	prior model.Decision
	// currentSources contains the sources returned to reconciliation policy.
	currentSources []model.Source
	// oldSource is the previous source when one exists.
	oldSource model.Source
	// oldSourceExists indicates an existing source renewal.
	oldSourceExists bool
	// written is the source supplied by the application.
	written model.Source
	// ensured records whether an identity was requested.
	ensured bool
	// saved records the reconciled decision.
	saved model.Decision
	// savedChanged records whether persistence was asked to revise state.
	savedChanged bool
	// savedTargets are destination identifiers supplied for delivery.
	savedTargets []string
}

// EnsureDecision records that reconciliation requested a stable decision identity.
func (p *policyTx) EnsureDecision(context.Context, string) error {
	p.ensured = true
	return nil
}

// Source returns the existing source and whether it exists.
func (p *policyTx) Source(context.Context, string, model.SourceKind) (model.Source, bool, error) {
	return p.oldSource, p.oldSourceExists, nil
}

// PutSource captures the source chosen by application policy.
func (p *policyTx) PutSource(_ context.Context, _ string, source model.Source) error {
	p.written = source
	p.currentSources = []model.Source{source}
	return nil
}

// Decision returns the previously persisted state.
func (p *policyTx) Decision(context.Context, string) (model.Decision, error) {
	return p.prior, nil
}

// Sources returns the currently active fake sources.
func (p *policyTx) Sources(context.Context, string, time.Time) ([]model.Source, error) {
	return p.currentSources, nil
}

// SaveDecision captures the reconciled state and its delivery destinations.
func (p *policyTx) SaveDecision(_ context.Context, _, next model.Decision, _ []model.Source, _ ChangeCause, changed bool, targets []string) error {
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
			oldSource:       model.Source{Kind: model.SourceManual, ExpiresAt: now.Add(time.Hour)},
			oldSourceExists: true,
		}
		err := ExtendSource(t.Context(), tx, "203.0.113.1", model.Source{
			Kind: model.SourceManual, ExpiresAt: now.Add(time.Minute), Reason: "renewal",
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
		err := ExtendSource(t.Context(), tx, "203.0.113.2", model.Source{
			Kind: model.SourceAutomatic, ExpiresAt: until,
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
		previous := model.Decision{ID: "id", IP: "203.0.113.3", State: model.DecisionUnbanned, Revision: 1}
		tx := &policyTx{
			prior:          previous,
			currentSources: []model.Source{{Kind: model.SourceManual, ExpiresAt: now.Add(time.Hour)}},
		}
		next, changed, err := ReconcileDecision(t.Context(), tx, previous.IP, now, []string{"cloudflare.edge"})

		require.NoError(t, err)
		assert.True(t, changed)
		assert.EqualValues(t, 2, next.Revision)
		assert.Equal(t, model.DecisionBanned, next.State)
		assert.Equal(t, next, tx.saved)
		assert.Equal(t, []string{"cloudflare.edge"}, tx.savedTargets)
	})

	t.Run("does not change revision when effective policy is unchanged", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		previous := model.Decision{
			ID: "id", IP: "203.0.113.4", State: model.DecisionBanned,
			Revision: 4, ExpiresAt: now.Add(time.Hour),
		}
		tx := &policyTx{
			prior:          previous,
			currentSources: []model.Source{{Kind: model.SourceManual, ExpiresAt: previous.ExpiresAt}},
		}
		next, changed, err := ReconcileDecision(t.Context(), tx, previous.IP, now, nil)

		require.NoError(t, err)
		assert.False(t, changed)

		expected := previous
		expected.ExpiresAt = previous.ExpiresAt.UTC()
		assert.Equal(t, expected, next)
		assert.False(t, tx.savedChanged)
	})
}

// DecisionByID returns an active decision for workflow tests.
func (p *policyTx) DecisionByID(context.Context, string) (model.Decision, error) {
	return p.prior, nil
}

// DeleteSources clears all reasons inside the test transaction.
func (p *policyTx) DeleteSources(context.Context, string) error {
	p.currentSources = nil
	return nil
}

// ResetFailures accepts the observation generation change in the test transaction.
func (p *policyTx) ResetFailures(context.Context, string) error { return nil }

// ExpiredSourceIPs returns addresses with elapsed reasons in the test transaction.
func (p *policyTx) ExpiredSourceIPs(context.Context, time.Time) ([]string, error) {
	return nil, nil
}

// DeleteExpiredSources accepts an expiry operation in the test transaction.
func (p *policyTx) DeleteExpiredSources(context.Context, time.Time) error { return nil }

// Record returns the latest decision from the test transaction.
func (p *policyTx) Record(context.Context, string, time.Time) (model.Record, error) {
	return model.Record{Decision: p.saved}, nil
}
