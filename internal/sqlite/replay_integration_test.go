package sqlite_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/providers/cloudflare"
)

func TestDeliveryReplayAfterRestart(t *testing.T) {
	t.Parallel()

	t.Run("reconciles an already applied block and release without duplicating remote changes", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		var remote []map[string]any
		var created, deleted int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			switch r.Method {
			case http.MethodGet:
				assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"success": true, "result": remote}))
			case http.MethodPost:
				var block map[string]any
				if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				block["id"] = "owned"
				remote = append(remote, block)
				created++
				_, _ = w.Write([]byte(`{"success":true}`))
			case http.MethodDelete:
				assert.Equal(t, "/rules/owned", r.URL.Path)
				remote = nil
				deleted++
				_, _ = w.Write([]byte(`{"success":true}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		provider := cloudflare.Provider{RulesURL: server.URL + "/rules", Token: "secret", Client: server.Client()}
		path := filepath.Join(t.TempDir(), "state.db")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, _ := openStore(t, path, "cloudflare.edge")
		t.Cleanup(func() {
			if store != nil {
				assert.NoError(t, store.Close())
			}
		})
		ban, err := store.ApplyManualBan(ctx, "203.0.113.25", now.Add(time.Hour), "incident", now)
		require.NoError(t, err)
		job, err := store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, provider.Apply(ctx, job.Decision))

		// Simulate a crash after the provider succeeded but before Finish commits.
		require.NoError(t, store.Close())
		store = nil
		store, _ = openStore(t, path, "cloudflare.edge")
		job, err = store.Next(ctx, now)
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, provider.Apply(ctx, job.Decision))
		require.NoError(t, store.Finish(ctx, *job, true, now))
		mu.Lock()
		assert.Equal(t, 1, created)
		mu.Unlock()
		pending, err := store.Next(ctx, now)
		require.NoError(t, err)
		assert.Nil(t, pending)

		_, err = store.ReleaseAllSources(ctx, ban.Decision.ID, now.Add(time.Second))
		require.NoError(t, err)
		job, err = store.Next(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
		require.NoError(t, provider.Apply(ctx, job.Decision))

		// Simulate another crash after release but before acknowledgement.
		require.NoError(t, store.Close())
		store = nil
		store, _ = openStore(t, path, "cloudflare.edge")
		job, err = store.Next(ctx, now.Add(time.Second))
		require.NoError(t, err)
		require.NotNil(t, job)
		require.NoError(t, provider.Apply(ctx, job.Decision))
		require.NoError(t, store.Finish(ctx, *job, true, now.Add(time.Second)))

		mu.Lock()
		assert.Equal(t, 1, created)
		assert.Equal(t, 1, deleted)
		assert.Empty(t, remote)
		mu.Unlock()
	})
}
