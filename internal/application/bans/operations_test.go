package bans

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// workflowTx extends the reconciliation fake with observable release operations.
type workflowTx struct {
	// policyTx supplies the reusable reconciliation test state.
	policyTx
	// expiredIPs selects addresses affected by expiry.
	expiredIPs []string
	// deletedSources records complete manual release cleanup.
	deletedSources bool
	// resetFailures records the observation-generation reset.
	resetFailures bool
	// deletedExpired records removal of elapsed sources.
	deletedExpired bool
}

func (w *workflowTx) DecisionByID(context.Context, string) (decisions.Decision, error) {
	return w.prior, nil
}

func (w *workflowTx) DeleteSources(context.Context, string) error {
	w.deletedSources = true
	w.currentSources = nil
	return nil
}

func (w *workflowTx) ResetFailures(context.Context, string) error {
	w.resetFailures = true
	return nil
}

func (w *workflowTx) ExpiredSourceIPs(context.Context, time.Time) ([]string, error) {
	return w.expiredIPs, nil
}

func (w *workflowTx) DeleteExpiredSources(context.Context, time.Time) error {
	w.deletedExpired = true
	w.currentSources = nil
	return nil
}

func (w *workflowTx) Record(context.Context, string, time.Time) (Record, error) {
	return Record{Decision: w.saved}, nil
}

// workflowWriter executes application operations against an isolated fake transaction.
type workflowWriter struct {
	// tx is the transaction supplied to application callbacks.
	tx *workflowTx
}

func (w workflowWriter) TransactBan(ctx context.Context, fn func(MutationTransaction) error) error {
	return fn(w.tx)
}

func TestBanWorkflows(t *testing.T) {
	t.Parallel()

	t.Run("manual ban extends a source and queues the calculated decision", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: decisions.Decision{
			ID: "id", IP: "203.0.113.10", State: decisions.StateUnbanned,
		}}}
		record, err := ApplyManualBan(t.Context(), workflowWriter{tx}, "203.0.113.10", now.Add(time.Hour), "investigation", now, []string{"edge"})

		require.NoError(t, err)
		assert.Equal(t, SourceManual, tx.written.Kind)
		assert.Equal(t, "investigation", tx.written.Reason)
		assert.Equal(t, decisions.StateBanned, record.Decision.State)
		assert.Equal(t, []string{"edge"}, tx.savedTargets)
	})

	t.Run("manual release clears sources and resets detection", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		previous := decisions.Decision{
			ID: "id", IP: "203.0.113.11", Revision: 4,
			State: decisions.StateBanned, ExpiresAt: now.Add(time.Hour),
		}
		tx := &workflowTx{policyTx: policyTx{
			prior:          previous,
			currentSources: []Source{{Kind: SourceManual, ExpiresAt: previous.ExpiresAt}},
		}}
		record, err := ReleaseAllSources(t.Context(), workflowWriter{tx}, previous.ID, now, []string{"edge"})

		require.NoError(t, err)
		assert.True(t, tx.deletedSources)
		assert.True(t, tx.resetFailures)
		assert.EqualValues(t, 5, record.Decision.Revision)
		assert.Equal(t, decisions.StateUnbanned, record.Decision.State)
		assert.Equal(t, []string{"edge"}, tx.savedTargets)
	})

	t.Run("release rejects already released decisions", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: decisions.Decision{
			ID: "id", IP: "203.0.113.12", State: decisions.StateUnbanned,
		}}}
		_, err := ReleaseAllSources(t.Context(), workflowWriter{tx}, "id", now, []string{"edge"})

		require.ErrorIs(t, err, ErrNotFound)
		assert.False(t, tx.deletedSources)
		assert.False(t, tx.resetFailures)
	})

	t.Run("expiry reconciles released decisions after deleting elapsed sources", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		previous := decisions.Decision{
			ID: "id", IP: "203.0.113.13", Revision: 4,
			State: decisions.StateBanned, ExpiresAt: now.Add(-time.Second),
		}
		tx := &workflowTx{
			policyTx: policyTx{prior: previous, currentSources: []Source{{
				Kind: SourceManual, ExpiresAt: previous.ExpiresAt,
			}}},
			expiredIPs: []string{previous.IP},
		}
		released, err := ExpireSources(t.Context(), workflowWriter{tx}, now, []string{"edge"})

		require.NoError(t, err)
		assert.True(t, tx.deletedExpired)
		require.Len(t, released, 1)
		assert.Equal(t, previous.ID, released[0].ID)
		assert.Equal(t, decisions.StateUnbanned, released[0].State)
		assert.EqualValues(t, 5, released[0].Revision)
	})
}
