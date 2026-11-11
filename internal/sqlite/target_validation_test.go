package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

func TestOpenRejectsRemovedManagedDestination(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		release bool
	}{
		{name: "active ban still owned by old destination"},
		{name: "unacknowledged release still requires old destination", release: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			path := filepath.Join(t.TempDir(), "warden.db")
			rule := detection.Rule{Threshold: 2, Window: time.Minute, Ban: 2 * time.Minute}
			store, err := Open(path, rule, []string{"old"})
			require.NoError(t, err)
			now := time.Now().UTC().Truncate(time.Millisecond)
			created, err := store.ApplyManualBan(ctx, "203.0.113.81", now.Add(time.Hour), "incident", now)
			require.NoError(t, err)
			if tc.release {
				_, err = store.ReleaseAllSources(ctx, created.Decision.ID, now.Add(time.Second))
				require.NoError(t, err)
			}
			require.NoError(t, store.Close())

			reopened, err := Open(path, rule, []string{"replacement"})
			require.ErrorContains(t, err, `destination "old" has managed decisions`)
			assert.Nil(t, reopened)

			// A failed startup must leave the previous configuration's durable
			// pending work intact, so restoring the destination is sufficient.
			reopened, err = Open(path, rule, []string{"old"})
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
			pending, err := reopened.Next(ctx, now.Add(time.Second))
			require.NoError(t, err)
			require.NotNil(t, pending)
			assert.Equal(t, created.Decision.ID, pending.Decision.ID)
		})
	}
}
