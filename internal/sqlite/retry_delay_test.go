package sqlite

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

func TestFinishRetryDelay(t *testing.T) {
	t.Parallel()

	t.Run("rejects nonpositive delay without an attempt", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := bans.ApplyManualBan(ctx, store, "203.0.113.91", now.Add(time.Hour), "incident", now, []string{"edge"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)

		err = store.Finish(ctx, *job, errors.New("failure"), actions.DefaultMaxAttempts, now, 0)
		require.ErrorContains(t, err, "retry delay")

		var attempts int
		require.NoError(t, store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM delivery_attempts").Scan(&attempts))
		assert.Zero(t, attempts)
	})

	t.Run("persists an application-supplied delay", func(t *testing.T) {
		t.Parallel()

		store := openAtomicityStore(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := bans.ApplyManualBan(ctx, store, "203.0.113.92", now.Add(time.Hour), "incident", now, []string{"edge"})
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)

		delay := 37 * time.Second
		require.NoError(t, store.Finish(ctx, *job, errors.New("failure"), actions.DefaultMaxAttempts, now, delay))

		var millis, retryAt int64
		require.NoError(t, store.db.QueryRowContext(ctx,
			"SELECT delay_ms, retry_at FROM destination_backoff WHERE destination = ?", "edge",
		).Scan(&millis, &retryAt))
		assert.Equal(t, delay.Milliseconds(), millis)
		assert.Equal(t, now.Add(delay).UnixMilli(), retryAt)
		next, err := store.Next(ctx, now.Add(delay))
		require.NoError(t, err)
		require.NotNil(t, next)
		assert.Equal(t, delay, next.PreviousDelay)
	})
}
