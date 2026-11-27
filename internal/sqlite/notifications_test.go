package sqlite

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
)

func TestNotificationQueue(t *testing.T) {
	t.Parallel()

	t.Run("persists selected destinations once and survives restart", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		path := filepath.Join(t.TempDir(), "warden.db")
		store, err := Open(path)
		require.NoError(t, err)
		t.Cleanup(func() {
			if store != nil {
				assert.NoError(t, store.Close())
			}
		})
		identities := map[string]string{"slack-ops": "one", "msteams-admin": "two", "unused": "three"}
		require.NoError(t, store.BindNotificationIdentities(ctx, identities))

		rule := ipRule(t, "notify", 2, 0)
		rule.Actions.Notify = []string{"slack-ops", "msteams-admin"}
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{})
		require.NoError(t, err)
		clock := func() time.Time { return now }
		_, err = service.Process(ctx, namedLogin(t, "one", "hq", "user", "203.0.113.1", now), clock)
		require.NoError(t, err)
		job, err := store.NextNotification(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, job)

		event := namedLogin(t, "two", "hq", "user", "203.0.113.1", now)
		result, err := service.Process(ctx, event, clock)
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		select {
		case <-store.NotificationChanges():
		default:
			assert.Fail(t, "expected committed notification wakeup")
		}
		select {
		case <-store.Changes():
			assert.Fail(t, "notification-only rule must not wake enforcement")
		default:
		}
		_, err = service.Process(ctx, event, clock)
		require.NoError(t, err)
		_, err = service.Process(ctx, namedLogin(t, "three", "hq", "user", "203.0.113.1", now), clock)
		require.NoError(t, err)
		require.NoError(t, store.Close())
		store = nil

		reopened, err := Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		require.NoError(t, reopened.BindNotificationIdentities(ctx, identities))
		job, err = reopened.NextNotification(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, "slack-ops", job.Destination)
		assert.Equal(t, result.Incidents[0].ID, job.Incident.ID)
		require.NoError(t, reopened.FinishNotification(ctx, *job, notifications.Complete(*job, nil, 3, now, time.Second)))
		job, err = reopened.NextNotification(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, "msteams-admin", job.Destination)
		require.NoError(t, reopened.FinishNotification(ctx, *job, notifications.Complete(*job, nil, 3, now, time.Second)))
		job, err = reopened.NextNotification(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, job)
	})

	t.Run("retries independently and preserves pending jobs through pruning", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		store := openAtomicityStore(t)
		require.NoError(t, store.BindNotificationIdentities(ctx, map[string]string{"slack-ops": "one", "siem": "two"}))
		rule := ipRule(t, "notify", 1, time.Minute)
		rule.Actions.Notify = []string{"slack-ops", "siem"}
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{ObserveOnly: true})
		require.NoError(t, err)
		result, err := service.Process(ctx, namedLogin(t, "one", "hq", "user", "203.0.113.1", now), func() time.Time { return now })
		require.NoError(t, err)
		assert.Nil(t, result.Decision)
		job, err := store.NextNotification(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.True(t, job.Incident.ObserveOnly)
		assert.Equal(t, "slack-ops", job.Destination)
		require.NoError(t, store.FinishNotification(ctx, *job, notifications.Complete(*job, errors.New("receiver unavailable"), 2, now, time.Minute)))
		require.ErrorContains(t, store.BindNotificationIdentities(ctx, map[string]string{"slack-ops": "changed", "siem": "two"}), "pending deliveries")
		require.NoError(t, store.Prune(ctx, now, now))

		job, err = store.NextNotification(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, "siem", job.Destination)
		require.NoError(t, store.FinishNotification(ctx, *job, notifications.Complete(*job, nil, 2, now, time.Second)))
		job, err = store.NextNotification(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, job)
		deadline, err := store.NextNotificationDeadline(ctx)
		require.NoError(t, err)
		assert.Equal(t, now.Add(time.Minute), deadline)
		job, err = store.NextNotification(ctx, now.Add(time.Minute))
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, 1, job.Attempts)
		assert.Equal(t, time.Minute, job.Delay)
		require.NoError(t, store.FinishNotification(ctx, *job, notifications.Complete(*job, errors.New("receiver unavailable"), 2, now.Add(time.Minute), time.Minute)))
		job, err = store.NextNotification(ctx, now.Add(time.Hour))
		require.NoError(t, err)
		assert.Nil(t, job)
		require.NoError(t, store.BindNotificationIdentities(ctx, nil))
	})

	t.Run("rolls back an incident when its notification cannot be queued", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		now := time.Now().UTC()
		store := openAtomicityStore(t)
		rule := ipRule(t, "notify", 1, 0)
		rule.Actions.Notify = []string{"slack-ops"}
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{})
		require.NoError(t, err)
		event := namedLogin(t, "one", "hq", "user", "203.0.113.1", now)
		_, err = service.Process(ctx, event, func() time.Time { return now })
		require.Error(t, err)
		require.NoError(t, store.BindNotificationIdentities(ctx, map[string]string{"slack-ops": "one"}))
		result, err := service.Process(ctx, event, func() time.Time { return now })
		require.NoError(t, err)
		require.Len(t, result.Incidents, 1)
		assert.Equal(t, 1, result.Incidents[0].Count)
	})
}
