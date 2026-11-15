package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestValidateTargets(t *testing.T) {
	t.Parallel()

	t.Run("rejects removal with an active ban", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "warden.db")
		store, err := sqlite.Open(path)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := bans.ApplyManualBan(ctx, store, "203.0.113.81", now.Add(time.Hour), "incident", now, []string{"old"})
		require.NoError(t, err)
		require.NoError(t, store.Close())

		reopened, err := sqlite.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })

		require.ErrorContains(t, actions.ValidateTargets(ctx, reopened, []string{"replacement"}), `destination "old" has managed decisions`)
		require.NoError(t, actions.ValidateTargets(ctx, reopened, []string{"old"}))

		pending, err := reopened.Next(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, created.Decision.ID, pending.Decision.ID)
	})

	t.Run("rejects removal with an unacknowledged release", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		path := filepath.Join(t.TempDir(), "warden.db")
		store, err := sqlite.Open(path)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		created, err := bans.ApplyManualBan(ctx, store, "203.0.113.81", now.Add(time.Hour), "incident", now, []string{"old"})
		require.NoError(t, err)
		_, err = bans.ReleaseAllSources(ctx, store, created.Decision.ID, now.Add(time.Second), []string{"old"})
		require.NoError(t, err)
		require.NoError(t, store.Close())

		reopened, err := sqlite.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })

		require.ErrorContains(t, actions.ValidateTargets(ctx, reopened, []string{"replacement"}), `destination "old" has managed decisions`)
		require.NoError(t, actions.ValidateTargets(ctx, reopened, []string{"old"}))

		pending, err := reopened.Next(ctx, now.Add(2*time.Second))
		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, created.Decision.ID, pending.Decision.ID)
	})
}
