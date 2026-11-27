package sqlite_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestBanAdmission(t *testing.T) {
	t.Parallel()

	t.Run("protects automatic and manual bans", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "protected.db"), "edge")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		protection, err := bans.NewProtection([]string{"203.0.113.0/24"})
		require.NoError(t, err)
		policy := bans.Policy{Protection: protection}
		processor, err := ingestion.NewWithPolicy(store, ingestion.Rule{Threshold: 1, Window: time.Minute, Ban: time.Hour}, []string{"edge"}, policy)
		require.NoError(t, err)
		now := time.Now().UTC()
		event := failed("protected")
		event.IP = "::ffff:203.0.113.1"
		result, err := processor.Process(ctx, event, now)
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeProtected, result.Outcome)
		assert.Nil(t, result.Decision)
		admin, err := bans.NewAdminServiceWithPolicy(store, []string{"edge"}, policy)
		require.NoError(t, err)
		_, err = admin.BanManual(ctx, bans.ManualBanRequest{IP: event.IP, Duration: time.Hour, Reason: "test"}, now)
		require.ErrorIs(t, err, bans.ErrProtected)
		active, err := store.ListActive(ctx, now)
		require.NoError(t, err)
		assert.Empty(t, active)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, job)
	})

	t.Run("observe-only persists deduplicated hypothetical outcomes without decisions", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "observed.db"))
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		policy := bans.Policy{ObserveOnly: true}
		processor, err := ingestion.NewWithPolicy(store, ingestion.Rule{Threshold: 2, Window: time.Minute, Ban: time.Hour}, nil, policy)
		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		result, err := processor.Process(ctx, failed("one"), now)
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeBelowThreshold, result.Outcome)
		result, err = processor.Process(ctx, failed("two"), now)
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeObserved, result.Outcome)
		assert.Nil(t, result.Decision)
		result, err = processor.Process(ctx, failed("two"), now)
		require.NoError(t, err)
		assert.Equal(t, ingestion.OutcomeDuplicate, result.Outcome)
		service, err := overview.NewOperations(store)
		require.NoError(t, err)
		observations, err := service.Observations(ctx, 1)
		require.NoError(t, err)
		require.Len(t, observations.Items, 1)
		assert.Equal(t, "two", observations.Items[0].EventID)
		assert.Equal(t, now.Add(time.Hour), observations.Items[0].ExpiresAt)
		assert.Equal(t, 2, observations.Items[0].Failures)
		admin, err := bans.NewAdminServiceWithPolicy(store, nil, policy)
		require.NoError(t, err)
		_, err = admin.BanManual(ctx, bans.ManualBanRequest{IP: "203.0.113.1", Duration: time.Hour, Reason: "test"}, now)
		require.ErrorIs(t, err, bans.ErrObserveOnly)
		active, err := store.ListActive(ctx, now)
		require.NoError(t, err)
		assert.Empty(t, active)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, job)
		require.NoError(t, store.Prune(ctx, now))
		observations, err = service.Observations(ctx, 1)
		require.NoError(t, err)
		assert.Empty(t, observations.Items)
	})
}

func TestExplicitDeliveryRetry(t *testing.T) {
	t.Parallel()

	t.Run("preserves history and restores a fresh attempt budget for a failed unban", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "retry.db")
		store, _ := openStore(t, path, "edge")
		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(time.Hour), "investigation", now, []string{"edge"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, nil, 1, now, 0))
		released, err := bans.ReleaseAllSources(ctx, store, record.Decision.ID, now, []string{"edge"})
		require.NoError(t, err)
		job, err = store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("bad credentials"), 1, now, 10*time.Second))
		operations, err := overview.NewOperations(store)
		require.NoError(t, err)
		health, err := operations.Health(ctx)
		require.NoError(t, err)
		require.Len(t, health, 1)
		assert.EqualValues(t, 1, health[0].ExhaustedUnbans)
		retry, err := actions.NewRetryService(store, []string{"edge"})
		require.NoError(t, err)
		request := model.RetryRequest{DecisionID: released.Decision.ID, Revision: released.Decision.Revision, Destination: "edge", Actor: "operator"}
		stale := request
		stale.Revision = record.Decision.Revision
		require.ErrorIs(t, retry.Retry(ctx, stale, now), actions.ErrRetryConflict)
		require.NoError(t, retry.Retry(ctx, request, now.Add(time.Second)))
		require.ErrorIs(t, retry.Retry(ctx, request, now.Add(time.Second)), actions.ErrRetryConflict)
		require.NoError(t, store.Close())

		store, _ = openStore(t, path, "edge")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		require.NoError(t, store.ReconcileAttemptLimit(ctx, "edge", 2))
		job, err = store.Next(ctx, now.Add(11*time.Second))
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, released.Decision.Revision, job.Decision.Revision)
		require.NoError(t, store.Finish(ctx, *job, errors.New("still unavailable"), 2, now.Add(11*time.Second), 10*time.Second))
		require.NoError(t, store.ReconcileAttemptLimit(ctx, "edge", 2))
		current, err := store.GetDecision(ctx, released.Decision.ID, now.Add(11*time.Second))
		require.NoError(t, err)
		assert.Equal(t, model.DeliveryRetrying, current.CurrentDeliveries[0].Status)
		job, err = store.Next(ctx, now.Add(22*time.Second))
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, nil, 2, now.Add(22*time.Second), 0))
		current, err = store.GetDecision(ctx, released.Decision.ID, now.Add(22*time.Second))
		require.NoError(t, err)
		assert.Equal(t, released.Decision.Revision, current.Decision.Revision)
		require.Len(t, current.DeliveryHistory[0].Attempts, 3)
		assert.EqualValues(t, 1, current.DeliveryHistory[0].Attempts[0].Number)
		assert.EqualValues(t, 3, current.DeliveryHistory[0].Attempts[2].Number)
		assert.Equal(t, model.DeliveryDelivered, current.CurrentDeliveries[0].Status)
		operations, err = overview.NewOperations(store)
		require.NoError(t, err)
		timeline, err := operations.Timeline(ctx, released.Decision.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.1", timeline.IP)
		assert.Contains(t, timeline.Items, model.TimelineEvent{Kind: "retry", Action: "requested", Revision: released.Decision.Revision, Destination: "edge", Actor: "operator", At: now.Add(time.Second)})
		health, err = operations.Health(ctx)
		require.NoError(t, err)
		require.Len(t, health, 1)
		assert.Zero(t, health[0].FailedUnbans)
		assert.EqualValues(t, 1, health[0].Delivered)
	})

	t.Run("does not retry an expired ban", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		store, _ := openStore(t, filepath.Join(t.TempDir(), "expired.db"), "edge")
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		now := time.Now().UTC()
		record, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(time.Second), "test", now, []string{"edge"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, store.Finish(ctx, *job, errors.New("failure"), 1, now, 10*time.Second))
		service, err := actions.NewRetryService(store, []string{"edge"})
		require.NoError(t, err)
		require.ErrorIs(t, service.Retry(ctx, model.RetryRequest{DecisionID: record.Decision.ID, Revision: record.Decision.Revision, Destination: "edge", Actor: "operator"}, now.Add(2*time.Second)), actions.ErrRetryConflict)
	})
}
