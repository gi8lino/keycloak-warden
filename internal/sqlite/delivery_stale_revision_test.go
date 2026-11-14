package sqlite_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinishIgnoresStaleDeliveryFailure ensures old delivery failures cannot delay new revisions.
func TestFinishIgnoresStaleDeliveryFailure(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "test.db"), "edge")
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(time.Hour), "investigation", now, []string{"edge"})
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, first.Decision.Revision, job.Decision.Revision)

	// The desired state changes while the old revision is in flight.
	second, err := bans.ApplyManualBan(ctx, store, "203.0.113.1", now.Add(2*time.Hour), "extended", now, []string{"edge"})
	require.NoError(t, err)
	require.Greater(t, second.Decision.Revision, first.Decision.Revision)

	// A failed attempt against revision 1 must not postpone revision 2.
	require.NoError(t, store.Finish(ctx, *job, errors.New("provider failure"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(job.PreviousDelay)))
	pending, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, second.Decision, pending.Decision)
	record, err := store.GetDecision(ctx, first.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, record.DeliveryHistory, 2)
	old := record.DeliveryHistory[1]
	assert.Equal(t, "superseded", old.Status)
	assert.Equal(t, second.Decision.Revision, old.SupersededByRevision)
	require.Len(t, old.Attempts, 1)
	assert.Equal(t, "failed", old.Attempts[0].Outcome)
	assert.Nil(t, old.NextAttemptAt)
}

func TestDeliveryAttemptsSurviveRetryAndRestart(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "history.db")
	store, _ := openStore(t, path, "slack")
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, err := bans.ApplyManualBan(ctx, store, "192.0.2.5", now.Add(time.Hour), "test", now, []string{"slack"})
	require.NoError(t, err)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, errors.New("not_authed"), actions.DefaultMaxAttempts, now, actions.NextRetryDelay(job.PreviousDelay)))
	retry, err := store.GetDecision(ctx, record.Decision.ID, now)
	require.NoError(t, err)
	require.Len(t, retry.DeliveryHistory, 1)
	delivery := retry.DeliveryHistory[0]
	assert.Equal(t, "retrying", delivery.Status)
	require.NotNil(t, delivery.NextAttemptAt)
	next := *delivery.NextAttemptAt
	require.NoError(t, store.Finish(ctx, *job, nil, actions.DefaultMaxAttempts, next, 0))
	require.NoError(t, store.Close())

	reopened, _ := openStore(t, path, "slack")
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	result, err := reopened.GetDecision(ctx, record.Decision.ID, next)
	require.NoError(t, err)
	require.Len(t, result.DeliveryHistory, 1)
	delivery = result.DeliveryHistory[0]
	assert.Equal(t, "delivered", delivery.Status)
	assert.Equal(t, "banned", delivery.DesiredState)
	assert.Equal(t, &next, delivery.AcknowledgedAt)
	assert.Nil(t, delivery.NextAttemptAt)
	require.Len(t, delivery.Attempts, 2)
	assert.EqualValues(t, 1, delivery.Attempts[0].Number)
	assert.Equal(t, now, delivery.Attempts[0].At)
	assert.Equal(t, "not_authed", delivery.Attempts[0].Error)
	assert.EqualValues(t, 2, delivery.Attempts[1].Number)
	assert.Equal(t, "succeeded", delivery.Attempts[1].Outcome)
	assert.Empty(t, delivery.Attempts[1].Error)
}
