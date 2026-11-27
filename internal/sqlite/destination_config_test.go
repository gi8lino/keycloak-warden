package sqlite

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

func TestConfigureDestinations(t *testing.T) {
	t.Parallel()

	t.Run("rolls back enforcement identity when notification admission fails", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		require.NoError(t, store.BindTargetIdentities(ctx, map[string]string{"edge": "old"}))
		require.NoError(t, store.BindNotificationIdentities(ctx, map[string]string{"audit": "original"}))
		rule := ipRule(t, "audit", 1, 0)
		rule.Actions.Notify = []string{"audit"}
		service, err := ingestion.New(store, []detection.Rule{rule}, nil, bans.Policy{})
		require.NoError(t, err)
		_, err = service.Process(ctx, namedLogin(t, "one", "hq", "user", "203.0.113.1", now), func() time.Time { return now })
		require.NoError(t, err)

		err = store.ConfigureDestinations(ctx, map[string]string{"edge": "new"}, map[string]string{"audit": "reassigned"}, func(enforcement.AttemptLimitReconciler) error { return nil })
		require.ErrorContains(t, err, "pending deliveries")
		var identity string
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT identity FROM target_identities WHERE name = 'edge'").Scan(&identity))
		assert.Equal(t, "old", identity)
	})

	t.Run("rolls back both identity sets when budget reconciliation fails", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		require.NoError(t, store.BindTargetIdentities(ctx, map[string]string{"edge": "old"}))
		require.NoError(t, store.BindNotificationIdentities(ctx, map[string]string{"audit": "original"}))

		err := store.ConfigureDestinations(ctx, map[string]string{"edge": "new"}, map[string]string{"audit": "new"}, func(r enforcement.AttemptLimitReconciler) error {
			return r.ReconcileAttemptLimit(ctx, "edge", 0)
		})
		require.ErrorContains(t, err, "max-attempts")
		var edge, audit string
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT identity FROM target_identities WHERE name = 'edge'").Scan(&edge))
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT identity FROM notification_identities WHERE name = 'audit'").Scan(&audit))
		assert.Equal(t, "old", edge)
		assert.Equal(t, "original", audit)
	})

	t.Run("commits both identity sets", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		require.NoError(t, store.ConfigureDestinations(ctx, map[string]string{"edge": "zone"}, map[string]string{"audit": "receiver"}, func(r enforcement.AttemptLimitReconciler) error {
			return r.ReconcileAttemptLimit(ctx, "edge", 3)
		}))
		var edge, audit string
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT identity FROM target_identities WHERE name = 'edge'").Scan(&edge))
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT identity FROM notification_identities WHERE name = 'audit'").Scan(&audit))
		assert.Equal(t, "zone", edge)
		assert.Equal(t, "receiver", audit)
	})
}
