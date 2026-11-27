package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestTransactObservation(t *testing.T) {
	t.Parallel()

	t.Run("duplicates and nonmatching events never reach threshold", func(t *testing.T) {
		t.Parallel()

		store, processor := openStore(t, filepath.Join(t.TempDir(), "test.db"))
		defer store.Close() // nolint:errcheck
		now := time.Now()
		ok := failed("success")
		ok.User.Type = "LOGIN"
		noIP := failed("missing")
		noIP.User.IP = ""
		decision, err := processDecision(processor, t.Context(), failed("same"), now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), failed("same"), now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), ok, now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), noIP, now)

		require.NoError(t, err)
		assert.Nil(t, decision)
		decision, err = processDecision(processor, t.Context(), failed("outside-window"), now.Add(time.Minute))

		require.NoError(t, err)
		assert.Nil(t, decision)
	})

	t.Run("concurrent replays count once", func(t *testing.T) {
		t.Parallel()

		store, processor := openStore(t, filepath.Join(t.TempDir(), "test.db"))
		defer store.Close() // nolint:errcheck
		var wg sync.WaitGroup
		now := time.Now()
		for range 12 {
			wg.Go(func() {
				decision, err := processDecision(processor, context.Background(), failed("repeat"), now)

				assert.NoError(t, err)
				assert.Nil(t, decision)
			})
		}
		wg.Wait()
		decision, err := processDecision(processor, t.Context(), failed("next"), now)

		require.NoError(t, err)
		require.NotNil(t, decision)
	})
}

// TestTransactionLifecycle verifies that both application interfaces share atomic commit and rollback semantics.
func TestTransactionLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("observation transactions can persist failures and ban sources atomically", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "observation.db"))
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		ip := "203.0.113.92"
		event := events.Envelope{
			Version: events.SchemaVersion,
			ID:      "observation-1",
			Source:  events.SourceKeycloak,
			Kind:    events.KindUser,
			User: &events.UserEvent{
				Type: events.TypeLoginError,
				IP:   ip,
			},
		}

		err := store.TransactObservation(ctx, func(tx ingestion.Transaction) error {
			inserted, err := tx.RecordEvent(ctx, event, now, true)
			if err != nil {
				return err
			}
			assert.True(t, inserted)

			if err := tx.EnsureDecision(ctx, ip); err != nil {
				return err
			}
			return tx.PutSource(ctx, ip, model.Source{
				Kind:      model.SourceAutomatic,
				ExpiresAt: now.Add(time.Hour),
			})
		})
		require.NoError(t, err)

		select {
		case <-store.Changes():
		default:
			require.FailNow(t, "committed source change must notify the worker")
		}

		err = store.TransactObservation(ctx, func(tx ingestion.Transaction) error {
			count, err := tx.CountMatches(ctx, (detection.Rule{
				Name: "brute-force",
				Selector: detection.Selector{
					Kind:   events.KindUser,
					Events: []string{events.TypeLoginError},
				},
				Aggregation: detection.Aggregation{
					GroupBy:   detection.GroupIP,
					Threshold: 1,
					Window:    time.Minute,
				},
				Actions: detection.Actions{
					Ban: time.Second,
				},
			}).Query(event, now))
			if err != nil {
				return err
			}
			assert.Equal(t, 1, count)
			return nil
		})
		require.NoError(t, err)

		select {
		case <-store.Changes():
			require.FailNow(t, "read-only observation transaction must not notify the worker")
		default:
		}
	})

	t.Run("ban transactions roll back source mutations without notification", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "ban.db"))
		t.Cleanup(func() { assert.NoError(t, store.Close()) })

		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		ip := "203.0.113.93"
		rollback := errors.New("injected rollback")

		err := store.TransactDecision(ctx, func(tx bans.MutationTransaction) error {
			if err := tx.EnsureDecision(ctx, ip); err != nil {
				return err
			}
			if err := tx.PutSource(ctx, ip, model.Source{
				Kind:      model.SourceManual,
				ExpiresAt: now.Add(time.Hour),
				Reason:    "investigation",
			}); err != nil {
				return err
			}
			return rollback
		})
		require.ErrorIs(t, err, rollback)

		err = store.TransactDecision(ctx, func(tx bans.MutationTransaction) error {
			_, err := tx.Decision(ctx, ip)
			return err
		})
		require.ErrorIs(t, err, sql.ErrNoRows)

		select {
		case <-store.Changes():
			require.FailNow(t, "rolled-back ban transaction must not notify the worker")
		default:
		}
	})
}
