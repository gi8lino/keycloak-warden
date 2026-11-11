package sqlite

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorruptedBanRowsReturnErrors(t *testing.T) {
	t.Parallel()

	// SQLite's dynamic typing permits existing rows to contain nonnumeric
	// values even in INTEGER-affinity columns. Do not silently return a
	// partial ban list or a decision missing its sources or acknowledgements.
	cases := []struct {
		name   string
		update string
	}{
		{
			name:   "decision revision is not an integer",
			update: "UPDATE decisions SET revision = 'corrupt' WHERE ip = ?",
		},
		{
			name:   "source expiry is not an integer",
			update: "UPDATE ban_sources SET expires = 'corrupt' WHERE ip = ?",
		},
		{
			name:   "delivery acknowledgement is not an integer",
			update: "UPDATE deliveries SET acknowledged = 'corrupt' WHERE ip = ?",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := openAtomicityStore(t, "edge")
			ctx := t.Context()
			now := time.Now().UTC().Truncate(time.Millisecond)
			created, err := store.ApplyManualBan(ctx, "203.0.113.71", now.Add(time.Hour), "investigation", now)
			require.NoError(t, err)

			_, err = store.db.ExecContext(ctx, tc.update, created.Decision.IP)
			require.NoError(t, err)

			list, err := store.ListActive(ctx, now)
			require.Error(t, err)
			assert.Nil(t, list, "must not return a partial active-ban list")

			_, err = store.GetDecision(ctx, created.Decision.ID, now)
			require.Error(t, err, "must not return an incomplete ban record")
		})
	}
}
