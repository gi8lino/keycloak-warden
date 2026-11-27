package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// openStore constructs an isolated store and matching application ingestion use case.
func openStore(t *testing.T, path string, targets ...string) (*sqlite.Store, *ingestion.Service) {
	t.Helper()

	rule := detection.Rule{
		Name: "brute-force",
		Selector: detection.Selector{
			Kind:   events.KindUser,
			Events: []string{events.TypeLoginError},
		},
		Aggregation: detection.Aggregation{
			GroupBy:   detection.GroupIP,
			Threshold: 2,
			Window:    time.Minute,
		},
		Actions: detection.Actions{
			Ban: 2 * time.Minute,
		},
	}
	store, err := sqlite.Open(path)
	require.NoError(t, err)

	require.NoError(t, enforcement.ValidateTargets(t.Context(), store, targets))

	processor, err := ingestion.New(store, []detection.Rule{rule}, targets, bans.Policy{})
	require.NoError(t, err)

	return store, processor
}

// processDecision extracts a changed decision from an ingestion outcome for storage tests.
func processDecision(
	processor *ingestion.Service,
	ctx context.Context,
	event events.Envelope,
	now time.Time,
) (*model.Decision, error) {
	result, err := processor.Process(ctx, event, func() time.Time { return now })
	return result.Decision, err
}

// failed constructs a distinct Keycloak failed login from one stable client address.
func failed(id string) events.Envelope {
	return events.Envelope{
		ID:        id,
		Source:    events.SourceKeycloak,
		Kind:      events.KindUser,
		Version:   events.SchemaVersion,
		Timestamp: time.Date(2026, time.November, 5, 15, 0, 0, 0, time.UTC),
		User: &events.UserEvent{
			Type: events.TypeLoginError,
			IP:   "203.0.113.1",
		},
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	t.Run("restart retains work and expiry releases each destination independently", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "test.db")
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		store, processor := openStore(t, path, "a", "b")
		_, err := processDecision(processor, ctx, failed("one"), now)

		require.NoError(t, err)
		decision, err := processDecision(processor, ctx, failed("two"), now)

		require.NoError(t, err)
		require.NotNil(t, decision)
		require.NoError(t, store.Close())

		store, processor = openStore(t, path, "a", "b")
		defer store.Close() // nolint:errcheck
		a, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, a)
		assert.Equal(t, "a", a.Destination)
		assert.Zero(t, a.PreviousDelay)
		require.NoError(t, store.Finish(ctx, *a, errors.New("provider failure"), retry.DefaultMaxAttempts, now, retry.DefaultRetryPolicy().NextDelay(a.PreviousDelay)))
		b, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, b)
		assert.Equal(t, "b", b.Destination)
		require.NoError(t, store.Finish(ctx, *b, nil, retry.DefaultMaxAttempts, now, 0))
		retryJob, err := store.Next(ctx, now.Add(11*time.Second))

		require.NoError(t, err)
		require.NotNil(t, retryJob)
		assert.Equal(t, a.Decision, retryJob.Decision)
		assert.Equal(t, a.Destination, retryJob.Destination)
		assert.Equal(t, retry.DefaultInitialRetryDelay, retryJob.PreviousDelay)

		later := now.Add(time.Second)
		extended, err := processDecision(processor, ctx, failed("three"), later)

		require.NoError(t, err)
		require.NotNil(t, extended)
		assert.Equal(t, decision.ID, extended.ID)
		assert.Equal(t, int64(2), extended.Revision)
		require.NoError(t, store.Finish(ctx, *a, nil, retry.DefaultMaxAttempts, later, 0))
		pending, err := store.Next(ctx, later)

		require.NoError(t, err)
		require.NotNil(t, pending)
		assert.Equal(t, *extended, pending.Decision)
		active, err := store.ListActive(ctx, later)

		require.NoError(t, err)
		require.Len(t, active, 1)
		assert.Equal(t, extended, &active[0].Decision)
		view, err := store.GetDecision(ctx, extended.ID, later)

		require.NoError(t, err)
		assert.Equal(t, *extended, view.Decision)
		assert.Equal(
			t,
			[]model.Acknowledgement{{Destination: "a", Revision: 0}, {Destination: "b", Revision: 1}},
			view.Deliveries,
		)

		now = extended.ExpiresAt

		_, err = bans.ExpireSources(ctx, store, now, []string{"a", "b"})
		require.NoError(t, err)
		firstRelease, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, firstRelease)
		assert.Equal(t, model.DecisionUnbanned, firstRelease.Decision.State)
		assert.Equal(t, int64(3), firstRelease.Decision.Revision)
		require.NoError(t, store.Finish(ctx, *firstRelease, nil, retry.DefaultMaxAttempts, now, 0))

		secondRelease, err := store.Next(ctx, now)

		require.NoError(t, err)
		require.NotNil(t, secondRelease)
		assert.Equal(t, model.DecisionUnbanned, secondRelease.Decision.State)
		assert.Equal(t, int64(3), secondRelease.Decision.Revision)
		assert.ElementsMatch(t, []string{"a", "b"}, []string{firstRelease.Destination, secondRelease.Destination})
		require.NoError(t, store.Finish(ctx, *secondRelease, nil, retry.DefaultMaxAttempts, now, 0))

		noMoreWork, err := store.Next(ctx, now)

		require.NoError(t, err)
		assert.Nil(t, noMoreWork)

		releasedRecord, err := store.GetDecision(ctx, extended.ID, now)

		require.NoError(t, err)
		assert.Equal(t, []model.Acknowledgement{
			{Destination: "a", Revision: 3},
			{Destination: "b", Revision: 3},
		}, releasedRecord.Deliveries)

		active, err = store.ListActive(ctx, now)

		require.NoError(t, err)
		assert.Empty(t, active)
	})
}

// TestAdditionalFailureDoesNotReviseUnchangedBan ensures observation counts do not trigger delivery revisions.
func TestAdditionalFailureDoesNotReviseUnchangedBan(t *testing.T) {
	t.Parallel()

	store, processor := openStore(t, filepath.Join(t.TempDir(), "state.db"), "receiver")
	defer store.Close() //nolint:errcheck
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err := processDecision(processor, ctx, failed("first"), now)
	require.NoError(t, err)
	original, err := processDecision(processor, ctx, failed("second"), now)
	require.NoError(t, err)
	require.NotNil(t, original)
	job, err := store.Next(ctx, now)
	require.NoError(t, err)
	require.NotNil(t, job)
	require.NoError(t, store.Finish(ctx, *job, nil, retry.DefaultMaxAttempts, now, 0))

	latest, err := processor.Process(ctx, failed("third"), func() time.Time { return now })
	require.NoError(t, err)
	assert.Equal(t, ingestion.OutcomeUnchanged, latest.Outcome)
	assert.Nil(t, latest.Decision, "an extra observation must not be reported as a new decision")
	record, err := store.GetDecision(ctx, original.ID, now)
	require.NoError(t, err)
	assert.Equal(t, *original, record.Decision)
	next, err := store.Next(ctx, now)
	require.NoError(t, err)
	assert.Nil(t, next, "an unchanged ban must not be delivered again")
}

func TestOpenValidation(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing database directory", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "missing-directory", "state.db")
		store, err := sqlite.Open(path)
		require.Error(t, err)
		assert.Nil(t, store)
	})
}

func TestStoreClosedErrors(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, store.Close())

	assert.Error(t, store.Ping(t.Context()))
	assert.Error(t, store.Prune(t.Context(), time.Now(), time.Now()))
	_, err := store.Next(t.Context(), time.Now())
	assert.Error(t, err)
	_, err = store.NextDeadline(t.Context())
	assert.Error(t, err)
	_, err = bans.ExpireSources(t.Context(), store, time.Now(), nil)
	assert.Error(t, err)
	assert.Error(t, store.TransactObservation(t.Context(), func(ingestion.Transaction) error {
		return errors.New("should not be invoked")
	}))
}
