package sqlite_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestRevisionJournal(t *testing.T) {
	t.Parallel()

	t.Run("captures reasons and release as separate immutable revisions", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "history.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"webhook.receiver"})
		require.NoError(t, err)
		viewer, err := overview.NewService(store)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		ban, err := service.BanManual(t.Context(), model.ManualBanRequest{
			IP: "203.0.113.40", Duration: time.Hour, Reason: "manual investigation",
		}, now)
		require.NoError(t, err)
		released, err := service.Release(t.Context(), ban.Decision.ID, now.Add(time.Minute))
		require.NoError(t, err)
		assert.Equal(t, model.DecisionUnbanned, released.Decision.State)

		page, err := viewer.Revisions(t.Context(), 1, "203.0.113.40", "")
		require.NoError(t, err)
		require.Len(t, page.Items, 2)
		assert.Equal(t, released.Decision.Revision, page.Items[0].Revision)
		assert.Equal(t, model.DecisionUnbanned, page.Items[0].State)
		assert.Empty(t, page.Items[0].Sources)
		assert.Equal(t, ban.Decision.Revision, page.Items[1].Revision)
		assert.Equal(t, model.DecisionBanned, page.Items[1].State)
		require.Len(t, page.Items[1].Sources, 1)
		assert.Equal(t, "manual investigation", page.Items[1].Sources[0].Reason)
		assert.False(t, page.Items[1].ChangedAt.IsZero())
		assert.Zero(t, page.NextPage)
	})

	t.Run("does not record a revision for an unchanged extension", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "history.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"edge"})
		require.NoError(t, err)
		viewer, err := overview.NewService(store)
		require.NoError(t, err)

		now := time.Now().UTC()
		first, err := service.BanManual(t.Context(), model.ManualBanRequest{IP: "203.0.113.41", Duration: time.Hour, Reason: "first"}, now)
		require.NoError(t, err)
		second, err := service.BanManual(t.Context(), model.ManualBanRequest{IP: "203.0.113.41", Duration: time.Minute, Reason: "reason updated"}, now)
		require.NoError(t, err)
		assert.Equal(t, first.Decision.Revision, second.Decision.Revision)
		page, err := viewer.Revisions(t.Context(), 1, "203.0.113.41", "")
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		assert.Equal(t, "first", page.Items[0].Sources[0].Reason)
	})
}

func TestDeliveryOverview(t *testing.T) {
	t.Parallel()

	t.Run("includes an exhausted release and its last provider failure", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "deliveries.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"webhook.receiver"})
		require.NoError(t, err)
		viewer, err := overview.NewService(store)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		ban, err := service.BanManual(t.Context(), model.ManualBanRequest{IP: "203.0.113.42", Duration: time.Hour, Reason: "test"}, now)
		require.NoError(t, err)
		_, err = service.Release(t.Context(), ban.Decision.ID, now.Add(time.Second))
		require.NoError(t, err)
		job, err := store.Next(t.Context(), now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, model.DecisionUnbanned, job.Decision.State)
		require.NoError(t, store.Finish(t.Context(), *job, errors.New("receiver rejected"), 1, now.Add(2*time.Second), actions.DefaultRetryPolicy().NextDelay(0)))

		page, err := viewer.Deliveries(t.Context(), 1, model.DeliveryExhausted, "webhook.receiver")
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		entry := page.Items[0]
		assert.Equal(t, ban.Decision.ID, entry.DecisionID)
		assert.Equal(t, model.DecisionUnbanned, entry.DesiredState)
		assert.Equal(t, model.DeliveryExhausted, entry.Status)
		assert.Equal(t, int64(1), entry.AttemptCount)
		assert.Equal(t, "receiver rejected", entry.LastError)
		assert.Zero(t, entry.AcknowledgedRevision)
	})

	t.Run("excludes superseded revisions from the current overview", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "deliveries.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"edge"})
		require.NoError(t, err)
		viewer, err := overview.NewService(store)
		require.NoError(t, err)
		now := time.Now().UTC()
		_, err = service.BanManual(t.Context(), model.ManualBanRequest{IP: "203.0.113.43", Duration: time.Hour, Reason: "first"}, now)
		require.NoError(t, err)
		_, err = service.BanManual(t.Context(), model.ManualBanRequest{IP: "203.0.113.43", Duration: 2 * time.Hour, Reason: "extended"}, now)
		require.NoError(t, err)
		page, err := viewer.Deliveries(t.Context(), 1, "", "edge")
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		assert.Equal(t, int64(2), page.Items[0].Revision)
	})
}

func TestRevisionJournalAtomicity(t *testing.T) {
	t.Parallel()

	t.Run("rolls back decision and sources when journal insert fails", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "atomic.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		viewer, err := overview.NewService(store)
		require.NoError(t, err)
		now := time.Now().UTC()

		err = store.TransactDecision(t.Context(), func(tx bans.MutationTransaction) error {
			if err := bans.ExtendSource(t.Context(), tx, "203.0.113.50", model.Source{
				Kind: model.SourceManual, Reason: "rolled back", ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				return err
			}
			_, _, err := bans.ReconcileDecisionWithCause(t.Context(), tx, "203.0.113.50", now, []string{"edge"}, bans.ChangeCause("invalid"))
			return err
		})
		require.Error(t, err)

		revisions, err := viewer.Revisions(t.Context(), 1, "203.0.113.50", "")
		require.NoError(t, err)
		assert.Empty(t, revisions.Items)
		active, err := store.ListActive(t.Context(), now)
		require.NoError(t, err)
		assert.Empty(t, active)
	})
}

func TestRevisionJournalPagination(t *testing.T) {
	t.Parallel()

	t.Run("bounds each page to twenty changes", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "pagination.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"edge"})
		require.NoError(t, err)
		viewer, err := overview.NewService(store)
		require.NoError(t, err)
		now := time.Now().UTC()

		// Seed one decision with a series of real revisions. These are fixture
		// operations, not generated test cases; the test remains one explicit subtest.
		for i := 0; i < 21; i++ {
			_, err := service.BanManual(t.Context(), model.ManualBanRequest{
				IP: "203.0.113.60", Duration: time.Duration(i+1) * time.Hour, Reason: "extension",
			}, now)
			require.NoError(t, err)
		}
		first, err := viewer.Revisions(t.Context(), 1, "203.0.113.60", "")
		require.NoError(t, err)
		assert.Len(t, first.Items, 20)
		assert.Equal(t, 2, first.NextPage)

		second, err := viewer.Revisions(t.Context(), 2, "203.0.113.60", "")
		require.NoError(t, err)
		assert.Len(t, second.Items, 1)
		assert.Zero(t, second.NextPage)
	})
}

func TestSourceChangeJournal(t *testing.T) {
	t.Parallel()

	t.Run("records edits without revising the effective decision", func(t *testing.T) {
		t.Parallel()

		store, err := sqlite.Open(filepath.Join(t.TempDir(), "source-audit.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })

		service, err := bans.NewAdminService(store, []string{"webhook.receiver"})
		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)

		created, err := service.BanManual(t.Context(), model.ManualBanRequest{
			IP: "203.0.113.119", Duration: time.Hour, Reason: "first",
		}, now)
		require.NoError(t, err)
		updated, err := service.BanManual(t.Context(), model.ManualBanRequest{
			IP: "203.0.113.119", Duration: time.Minute, Reason: "second",
		}, now)
		require.NoError(t, err)

		assert.Equal(t, created.Decision.Revision, updated.Decision.Revision)
		require.Len(t, updated.SourceChanges, 2)
		assert.Equal(t, "updated", updated.SourceChanges[0].Action)
		assert.Equal(t, "second", updated.SourceChanges[0].Reason)
		assert.Equal(t, "added", updated.SourceChanges[1].Action)
		assert.Equal(t, "first", updated.SourceChanges[1].Reason)
		assert.Greater(t, updated.SourceChanges[0].ID, updated.SourceChanges[1].ID)

		released, err := service.Release(t.Context(), created.Decision.ID, now.Add(time.Minute))
		require.NoError(t, err)
		require.Len(t, released.SourceChanges, 3)
		assert.Equal(t, "removed", released.SourceChanges[0].Action)
		assert.Equal(t, "second", released.SourceChanges[0].Reason)
	})

	t.Run("rolls back source events when the decision transaction fails", func(t *testing.T) {
		t.Parallel()

		store, err := sqlite.Open(filepath.Join(t.TempDir(), "source-rollback.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"edge"})
		require.NoError(t, err)
		now := time.Now().UTC()
		created, err := service.BanManual(t.Context(), model.ManualBanRequest{
			IP: "203.0.113.120", Duration: time.Hour, Reason: "original",
		}, now)
		require.NoError(t, err)

		err = store.TransactDecision(t.Context(), func(tx bans.MutationTransaction) error {
			if err := tx.PutSource(t.Context(), "203.0.113.120", model.Source{
				Kind: model.SourceManual, ExpiresAt: now.Add(time.Hour), Reason: "rolled back",
			}); err != nil {
				return err
			}
			return errors.New("abort before commit")
		})
		require.Error(t, err)
		after, err := service.GetDecision(t.Context(), created.Decision.ID, now)
		require.NoError(t, err)
		require.Len(t, after.SourceChanges, 1)
		assert.Equal(t, "added", after.SourceChanges[0].Action)
	})
}

func TestCurrentDeliveriesNotLimitedByHistoryPage(t *testing.T) {
	t.Parallel()

	t.Run("returns every destination after the history page is capped", func(t *testing.T) {
		t.Parallel()

		targets := make([]string, 0, 20)
		for i := 0; i < 20; i++ {
			targets = append(targets, fmt.Sprintf("webhook.receiver-%02d", i))
		}
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "current-deliveries.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, targets)
		require.NoError(t, err)

		ban, err := service.BanManual(t.Context(), model.ManualBanRequest{
			IP: "203.0.113.121", Duration: time.Hour, Reason: "current status",
		}, time.Now().UTC())
		require.NoError(t, err)
		require.Len(t, ban.CurrentDeliveries, 20)

		page, err := service.GetDecision(t.Context(), ban.Decision.ID, time.Now())
		require.NoError(t, err)
		assert.Len(t, page.DeliveryHistory, 16)
		assert.Len(t, page.CurrentDeliveries, 20)
		assert.Equal(t, "webhook.receiver-19", page.CurrentDeliveries[19].Destination)
		assert.Equal(t, model.DeliveryPending, page.CurrentDeliveries[19].Status)
	})
}

func TestRevisionJournalStablePagination(t *testing.T) {
	t.Parallel()

	t.Run("does not shift older pages after a new revision is committed", func(t *testing.T) {
		t.Parallel()
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "pinned-revisions.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		service, err := bans.NewAdminService(store, []string{"edge"})
		require.NoError(t, err)
		viewer, err := overview.NewService(store)
		require.NoError(t, err)
		now := time.Now().UTC()

		for i := 0; i < 21; i++ {
			_, err := service.BanManual(t.Context(), model.ManualBanRequest{
				IP: "203.0.113.66", Duration: time.Duration(i+1) * time.Hour, Reason: "extension",
			}, now)
			require.NoError(t, err)
		}

		first, err := viewer.Revisions(t.Context(), 1, "203.0.113.66", "")
		require.NoError(t, err)
		require.Len(t, first.Items, 20)
		assert.Positive(t, first.ThroughSequence)

		_, err = service.BanManual(t.Context(), model.ManualBanRequest{
			IP: "203.0.113.66", Duration: 22 * time.Hour, Reason: "new revision",
		}, now)
		require.NoError(t, err)

		older, err := viewer.RevisionsThrough(t.Context(), 2, "203.0.113.66", "", first.ThroughSequence)
		require.NoError(t, err)
		require.Len(t, older.Items, 1)
		assert.Equal(t, int64(1), older.Items[0].Revision)
		assert.Zero(t, older.NextPage)
		assert.Equal(t, first.ThroughSequence, older.ThroughSequence)

		fresh, err := viewer.Revisions(t.Context(), 1, "203.0.113.66", "")
		require.NoError(t, err)
		assert.Greater(t, fresh.ThroughSequence, first.ThroughSequence)
		assert.Equal(t, int64(22), fresh.Items[0].Revision)
	})
}
