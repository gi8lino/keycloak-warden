package bans

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
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
	// commitErr simulates a transaction failure after the workflow completes.
	commitErr error
}

func (w workflowWriter) TransactDecision(_ context.Context, fn func(MutationTransaction) error) error {
	if err := fn(w.tx); err != nil {
		return err
	}
	return w.commitErr
}

func TestBanWorkflows(t *testing.T) {
	t.Parallel()

	t.Run("manual ban extends a source and queues the calculated decision", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: decisions.Decision{
			ID: "id", IP: "203.0.113.10", State: decisionstate.StateUnbanned,
		}}}
		record, err := ApplyManualBan(t.Context(), workflowWriter{tx: tx}, "203.0.113.10", now.Add(time.Hour), "investigation", now, []string{"edge"})

		require.NoError(t, err)
		assert.Equal(t, SourceManual, tx.written.Kind)
		assert.Equal(t, "investigation", tx.written.Reason)
		assert.Equal(t, decisionstate.StateBanned, record.Decision.State)
		assert.Equal(t, []string{"edge"}, tx.savedTargets)
	})

	t.Run("manual release clears sources and resets detection", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		previous := decisions.Decision{
			ID: "id", IP: "203.0.113.11", Revision: 4,
			State: decisionstate.StateBanned, ExpiresAt: now.Add(time.Hour),
		}
		tx := &workflowTx{policyTx: policyTx{
			prior:          previous,
			currentSources: []Source{{Kind: SourceManual, ExpiresAt: previous.ExpiresAt}},
		}}
		record, err := ReleaseAllSources(t.Context(), workflowWriter{tx: tx}, previous.ID, now, []string{"edge"})

		require.NoError(t, err)
		assert.True(t, tx.deletedSources)
		assert.True(t, tx.resetFailures)
		assert.EqualValues(t, 5, record.Decision.Revision)
		assert.Equal(t, decisionstate.StateUnbanned, record.Decision.State)
		assert.Equal(t, []string{"edge"}, tx.savedTargets)
	})

	t.Run("release rejects already released decisions", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: decisions.Decision{
			ID: "id", IP: "203.0.113.12", State: decisionstate.StateUnbanned,
		}}}
		_, err := ReleaseAllSources(t.Context(), workflowWriter{tx: tx}, "id", now, []string{"edge"})

		require.ErrorIs(t, err, ErrNotFound)
		assert.False(t, tx.deletedSources)
		assert.False(t, tx.resetFailures)
	})

	t.Run("expiry reconciles released decisions after deleting elapsed sources", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		previous := decisions.Decision{
			ID: "id", IP: "203.0.113.13", Revision: 4,
			State: decisionstate.StateBanned, ExpiresAt: now.Add(-time.Second),
		}
		tx := &workflowTx{
			policyTx: policyTx{prior: previous, currentSources: []Source{{
				Kind: SourceManual, ExpiresAt: previous.ExpiresAt,
			}}},
			expiredIPs: []string{previous.IP},
		}
		released, err := ExpireSources(t.Context(), workflowWriter{tx: tx}, now, []string{"edge"})

		require.NoError(t, err)
		assert.True(t, tx.deletedExpired)
		require.Len(t, released, 1)
		assert.Equal(t, previous.ID, released[0].ID)
		assert.Equal(t, decisionstate.StateUnbanned, released[0].State)
		assert.EqualValues(t, 5, released[0].Revision)
	})
}

// TestWorkflowCommitFailure ensures uncommitted records and releases never escape transactions.
func TestWorkflowCommitFailure(t *testing.T) {
	t.Parallel()

	t.Run("manual ban does not return a record on commit failure", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: decisions.Decision{
			ID: "decision", IP: "203.0.113.10", State: decisionstate.StateUnbanned,
		}}}
		writer := workflowWriter{tx: tx, commitErr: errors.New("commit failed")}

		record, err := ApplyManualBan(t.Context(), writer, "203.0.113.10", now.Add(time.Hour), "incident", now, []string{"edge"})

		require.ErrorContains(t, err, "commit failed")
		assert.Equal(t, Record{}, record)
	})

	t.Run("manual release does not return a record on commit failure", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		prior := decisions.Decision{
			ID: "decision", IP: "203.0.113.11", State: decisionstate.StateBanned,
			ExpiresAt: now.Add(time.Hour),
		}
		tx := &workflowTx{policyTx: policyTx{
			prior:          prior,
			currentSources: []Source{{Kind: SourceManual, ExpiresAt: prior.ExpiresAt}},
		}}
		writer := workflowWriter{tx: tx, commitErr: errors.New("commit failed")}

		record, err := ReleaseAllSources(t.Context(), writer, prior.ID, now, []string{"edge"})

		require.ErrorContains(t, err, "commit failed")
		assert.Equal(t, Record{}, record)
	})

	t.Run("expired releases are discarded on commit failure", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		prior := decisions.Decision{
			ID: "decision", IP: "203.0.113.12", State: decisionstate.StateBanned,
			ExpiresAt: now.Add(-time.Second),
		}
		tx := &workflowTx{
			policyTx: policyTx{prior: prior, currentSources: []Source{{
				Kind: SourceManual, ExpiresAt: prior.ExpiresAt,
			}}},
			expiredIPs: []string{prior.IP},
		}
		writer := workflowWriter{tx: tx, commitErr: errors.New("commit failed")}

		released, err := ExpireSources(t.Context(), writer, now, []string{"edge"})

		require.ErrorContains(t, err, "commit failed")
		assert.Nil(t, released)
	})
}
