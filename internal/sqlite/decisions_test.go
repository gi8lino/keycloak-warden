package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// TestDecisionIDsUseUUIDv7 ensures manual and automatic decisions receive standard UUIDv7 identifiers.
func TestDecisionIDsUseUUIDv7(t *testing.T) {
	t.Parallel()

	checkUUIDv7 := func(t *testing.T, id string) {
		t.Helper()

		parsed, err := uuid.Parse(id)
		require.NoError(t, err)
		assert.Equal(t, byte(7), parsed[6]>>4, "decision ID must use UUID version 7")
		assert.Equal(t, byte(0x80), parsed[8]&0xc0, "decision ID must use the RFC 9562 variant")
	}

	t.Run("manual ban", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "warden.db"))
		defer store.Close() //nolint:errcheck

		service, err := bans.NewAdminService(store, nil)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "203.0.113.50",
			Duration: time.Hour,
			Reason:   "incident",
		}, now)
		require.NoError(t, err)

		checkUUIDv7(t, record.Decision.ID)
	})

	t.Run("automatic ban", func(t *testing.T) {
		t.Parallel()

		store, processor := openStore(t, filepath.Join(t.TempDir(), "warden.db"))
		defer store.Close() //nolint:errcheck

		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := processDecision(processor, t.Context(), failed("uuidv7-first"), now)
		require.NoError(t, err)

		decision, err := processDecision(processor, t.Context(), failed("uuidv7-second"), now)
		require.NoError(t, err)
		require.NotNil(t, decision)

		checkUUIDv7(t, decision.ID)
	})
}

// TestDecisionStatePersistence verifies SQLite stores the public state values directly.
func TestDecisionStatePersistence(t *testing.T) {
	t.Parallel()

	t.Run("persists and reads banned decisions", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, _ := openStore(t, path, "edge")
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)

		created, err := bans.ApplyManualBan(ctx, store, "203.0.113.51", now.Add(time.Hour), "investigation", now, []string{"edge"})
		require.NoError(t, err)

		db, err := sql.Open("sqlite", path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, db.Close()) })

		var stored model.DecisionState
		require.NoError(t, db.QueryRowContext(ctx, "SELECT state FROM decisions WHERE ip = ?", created.Decision.IP).Scan(&stored))
		assert.Equal(t, model.DecisionBanned, stored)

		record, err := store.GetDecision(ctx, created.Decision.ID, now)
		require.NoError(t, err)
		assert.Equal(t, model.DecisionBanned, record.Decision.State)

		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, model.DecisionBanned, job.Decision.State)
	})

	t.Run("persists and reads unbanned decisions", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "warden.db")
		store, _ := openStore(t, path, "edge")
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)

		created, err := bans.ApplyManualBan(ctx, store, "203.0.113.52", now.Add(time.Hour), "investigation", now, []string{"edge"})
		require.NoError(t, err)
		_, err = bans.ReleaseAllSources(ctx, store, created.Decision.ID, now.Add(time.Second), []string{"edge"})
		require.NoError(t, err)

		db, err := sql.Open("sqlite", path)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, db.Close()) })

		var stored model.DecisionState
		require.NoError(t, db.QueryRowContext(ctx, "SELECT state FROM decisions WHERE ip = ?", created.Decision.IP).Scan(&stored))
		assert.Equal(t, model.DecisionUnbanned, stored)

		record, err := store.GetDecision(ctx, created.Decision.ID, now.Add(time.Second))
		require.NoError(t, err)
		assert.Equal(t, model.DecisionUnbanned, record.Decision.State)

		job, err := store.Next(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, model.DecisionUnbanned, job.Decision.State)
	})
}
