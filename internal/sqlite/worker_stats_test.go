package sqlite

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkerStats verifies only current-revision work is counted.
func TestWorkerStats(t *testing.T) {
	t.Parallel()

	t.Run("empty database has zero work", func(t *testing.T) {
		t.Parallel()

		store, err := Open(t.TempDir() + "/warden.db")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })

		stats, err := store.WorkerStats(t.Context(), time.Now())

		require.NoError(t, err)
		assert.Zero(t, stats.PendingDeliveries)
		assert.Zero(t, stats.RetryingDeliveries)
		assert.Zero(t, stats.ExhaustedDeliveries)
		assert.Zero(t, stats.ActiveBans)
		assert.Nil(t, stats.LastAttemptAt)
	})

	t.Run("counts only current revisions and unexpired sources", func(t *testing.T) {
		t.Parallel()

		store, err := Open(t.TempDir() + "/warden.db")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })

		now := time.Now().UTC().Truncate(time.Millisecond)
		future := now.Add(time.Hour).UnixMilli()
		past := now.Add(-time.Hour).UnixMilli()
		_, err = store.db.ExecContext(t.Context(), `
INSERT INTO decisions (ip,id,revision,state,expires) VALUES
 ('203.0.113.1','one',2,'banned',?),
 ('203.0.113.2','two',1,'banned',?);
`, future, past)
		require.NoError(t, err)

		_, err = store.db.ExecContext(t.Context(), `
INSERT INTO ban_sources (ip,kind,expires) VALUES
 ('203.0.113.1','automatic',?),
 ('203.0.113.2','automatic',?);
`, future, past)
		require.NoError(t, err)

		_, err = store.db.ExecContext(t.Context(), `
INSERT INTO delivery_history (ip,revision,destination,status) VALUES
 ('203.0.113.1',1,'webhook.old','exhausted'),
 ('203.0.113.1',2,'webhook.pending','pending'),
 ('203.0.113.1',2,'webhook.retry','retrying'),
 ('203.0.113.1',2,'webhook.exhausted','exhausted');
`)
		require.NoError(t, err)

		_, err = store.db.ExecContext(t.Context(), `
INSERT INTO delivery_attempts (ip,revision,destination,number,completed_at,error)
VALUES ('203.0.113.1',2,'webhook.retry',1,?,'retry');
`, now.UnixMilli())
		require.NoError(t, err)

		stats, err := store.WorkerStats(t.Context(), now)

		require.NoError(t, err)
		assert.Equal(t, 1, stats.PendingDeliveries)
		assert.Equal(t, 1, stats.RetryingDeliveries)
		assert.Equal(t, 1, stats.ExhaustedDeliveries)
		assert.Equal(t, 1, stats.ActiveBans)
		require.NotNil(t, stats.LastAttemptAt)
		assert.Equal(t, now, *stats.LastAttemptAt)
	})
}
