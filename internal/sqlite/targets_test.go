package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
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

		require.ErrorContains(t, enforcement.ValidateTargets(ctx, reopened, []string{"replacement"}), `destination "old" has managed decisions`)
		require.NoError(t, enforcement.ValidateTargets(ctx, reopened, []string{"old"}))

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

		require.ErrorContains(t, enforcement.ValidateTargets(ctx, reopened, []string{"replacement"}), `destination "old" has managed decisions`)
		require.NoError(t, enforcement.ValidateTargets(ctx, reopened, []string{"old"}))

		pending, err := reopened.Next(ctx, now.Add(2*time.Second))
		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, created.Decision.ID, pending.Decision.ID)
	})
}

func TestBindTargetIdentities(t *testing.T) {
	t.Parallel()

	t.Run("rejects reassignment while a ban is outstanding", func(t *testing.T) {
		t.Parallel()

		store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"))
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		ctx := t.Context()
		require.NoError(t, store.BindTargetIdentities(ctx, map[string]string{"edge": "zone-a"}))

		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err = bans.ApplyManualBan(ctx, store, "203.0.113.81", now.Add(time.Hour), "incident", now, []string{"edge"})
		require.NoError(t, err)

		require.ErrorContains(t, store.BindTargetIdentities(ctx, map[string]string{"edge": "zone-b"}), "changed identity")
		require.NoError(t, store.BindTargetIdentities(ctx, map[string]string{"edge": "zone-a"}))
	})

	t.Run("allows reassignment without obligations", func(t *testing.T) {
		t.Parallel()

		store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"))
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		require.NoError(t, store.BindTargetIdentities(t.Context(), map[string]string{"edge": "zone-a"}))
		require.NoError(t, store.BindTargetIdentities(t.Context(), map[string]string{"edge": "zone-b"}))
	})
}
