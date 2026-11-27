package bans

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/model"
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

// DecisionByID returns the decision selected for the workflow.
func (w *workflowTx) DecisionByID(context.Context, string) (model.Decision, error) {
	return w.prior, nil
}

// DeleteSources records the release and clears all fake sources.
func (w *workflowTx) DeleteSources(context.Context, string) error {
	w.deletedSources = true
	w.currentSources = nil
	return nil
}

// AdvanceBanGeneration records that the observation generation was advanced.
func (w *workflowTx) AdvanceBanGeneration(context.Context, string) error {
	w.resetFailures = true
	return nil
}

// ExpiredSourceIPs returns the addresses selected for expiry.
func (w *workflowTx) ExpiredSourceIPs(context.Context, time.Time) ([]string, error) {
	return w.expiredIPs, nil
}

// DeleteExpiredSources records expiry cleanup and clears the fake sources.
func (w *workflowTx) DeleteExpiredSources(context.Context, time.Time) error {
	w.deletedExpired = true
	w.currentSources = nil
	return nil
}

// Record returns the decision saved by the workflow.
func (w *workflowTx) Record(context.Context, string, time.Time) (model.Record, error) {
	return model.Record{Decision: w.saved}, nil
}

// workflowWriter executes application operations against an isolated fake transaction.
type workflowWriter struct {
	// tx is the transaction supplied to application callbacks.
	tx *workflowTx
	// commitErr simulates a transaction failure after the workflow completes.
	commitErr error
}

// TransactDecision applies the workflow before returning the simulated commit error.
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
		tx := &workflowTx{policyTx: policyTx{prior: model.Decision{
			ID: "id", IP: "203.0.113.10", State: model.DecisionUnbanned,
		}}}
		record, err := ApplyManualBan(t.Context(), workflowWriter{tx: tx}, "203.0.113.10", now.Add(time.Hour), "investigation", now, []string{"edge"})

		require.NoError(t, err)
		assert.Equal(t, model.SourceManual, tx.written.Kind)
		assert.Equal(t, "investigation", tx.written.Reason)
		assert.Equal(t, model.DecisionBanned, record.Decision.State)
		assert.Equal(t, []string{"edge"}, tx.savedTargets)
	})

	t.Run("manual release clears sources and resets detection", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		previous := model.Decision{
			ID: "id", IP: "203.0.113.11", Revision: 4,
			State: model.DecisionBanned, ExpiresAt: now.Add(time.Hour),
		}
		tx := &workflowTx{policyTx: policyTx{
			prior:          previous,
			currentSources: []model.Source{{Kind: model.SourceManual, ExpiresAt: previous.ExpiresAt}},
		}}
		record, err := ReleaseAllSources(t.Context(), workflowWriter{tx: tx}, previous.ID, now, []string{"edge"})

		require.NoError(t, err)
		assert.True(t, tx.deletedSources)
		assert.True(t, tx.resetFailures)
		assert.EqualValues(t, 5, record.Decision.Revision)
		assert.Equal(t, model.DecisionUnbanned, record.Decision.State)
		assert.Equal(t, []string{"edge"}, tx.savedTargets)
	})

	t.Run("release rejects already released decisions", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: model.Decision{
			ID: "id", IP: "203.0.113.12", State: model.DecisionUnbanned,
		}}}
		_, err := ReleaseAllSources(t.Context(), workflowWriter{tx: tx}, "id", now, []string{"edge"})

		require.ErrorIs(t, err, ErrNotFound)
		assert.False(t, tx.deletedSources)
		assert.False(t, tx.resetFailures)
	})

	t.Run("expiry reconciles released decisions after deleting elapsed sources", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		previous := model.Decision{
			ID: "id", IP: "203.0.113.13", Revision: 4,
			State: model.DecisionBanned, ExpiresAt: now.Add(-time.Second),
		}
		tx := &workflowTx{
			policyTx: policyTx{prior: previous, currentSources: []model.Source{{
				Kind: model.SourceManual, ExpiresAt: previous.ExpiresAt,
			}}},
			expiredIPs: []string{previous.IP},
		}
		released, err := ExpireSources(t.Context(), workflowWriter{tx: tx}, now, []string{"edge"})

		require.NoError(t, err)
		assert.True(t, tx.deletedExpired)
		require.Len(t, released, 1)
		assert.Equal(t, previous.ID, released[0].ID)
		assert.Equal(t, model.DecisionUnbanned, released[0].State)
		assert.EqualValues(t, 5, released[0].Revision)
	})
}

// TestWorkflowCommitFailure ensures uncommitted records and releases never escape transactions.
func TestWorkflowCommitFailure(t *testing.T) {
	t.Parallel()

	t.Run("manual ban does not return a record on commit failure", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		tx := &workflowTx{policyTx: policyTx{prior: model.Decision{
			ID: "decision", IP: "203.0.113.10", State: model.DecisionUnbanned,
		}}}
		writer := workflowWriter{tx: tx, commitErr: errors.New("commit failed")}

		record, err := ApplyManualBan(t.Context(), writer, "203.0.113.10", now.Add(time.Hour), "incident", now, []string{"edge"})

		require.ErrorContains(t, err, "commit failed")
		assert.Equal(t, model.Record{}, record)
	})

	t.Run("manual release does not return a record on commit failure", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		prior := model.Decision{
			ID: "decision", IP: "203.0.113.11", State: model.DecisionBanned,
			ExpiresAt: now.Add(time.Hour),
		}
		tx := &workflowTx{policyTx: policyTx{
			prior:          prior,
			currentSources: []model.Source{{Kind: model.SourceManual, ExpiresAt: prior.ExpiresAt}},
		}}
		writer := workflowWriter{tx: tx, commitErr: errors.New("commit failed")}

		record, err := ReleaseAllSources(t.Context(), writer, prior.ID, now, []string{"edge"})

		require.ErrorContains(t, err, "commit failed")
		assert.Equal(t, model.Record{}, record)
	})

	t.Run("expired releases are discarded on commit failure", func(t *testing.T) {
		t.Parallel()

		now := time.Now().UTC()
		prior := model.Decision{
			ID: "decision", IP: "203.0.113.12", State: model.DecisionBanned,
			ExpiresAt: now.Add(-time.Second),
		}
		tx := &workflowTx{
			policyTx: policyTx{prior: prior, currentSources: []model.Source{{
				Kind: model.SourceManual, ExpiresAt: prior.ExpiresAt,
			}}},
			expiredIPs: []string{prior.IP},
		}
		writer := workflowWriter{tx: tx, commitErr: errors.New("commit failed")}

		released, err := ExpireSources(t.Context(), writer, now, []string{"edge"})

		require.ErrorContains(t, err, "commit failed")
		assert.Nil(t, released)
	})
}
