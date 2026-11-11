package ingestion_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
)

// fakeRepository captures ingestion transactions for service tests.
type fakeRepository struct {
	// calls counts calls made to the fake repository.
	calls int
	// tx supplies the fake transaction used by the repository.
	tx *fakeTx
}

// Transact runs the application callback with the fake transaction.
func (r *fakeRepository) Transact(_ context.Context, apply func(ingestion.Transaction) error) error {
	r.calls++
	return apply(r.tx)
}

// fakeTx supplies controlled observation results for ingestion tests.
type fakeTx struct {
	// inserted controls whether the fake transaction treats an event as new.
	inserted bool
	// count supplies the failure count returned by the fake transaction.
	count int
	// blocked records whether the fake transaction applied the block operation.
	blocked bool
	// unchanged models a threshold hit that did not revise the effective decision.
	unchanged bool
}

// RecordFailure validates the test address and returns the configured insert result.
func (tx *fakeTx) RecordFailure(_ context.Context, event events.Event, _ time.Time) (bool, error) {
	if event.IP != netip.MustParseAddr("203.0.113.5") {
		return false, errors.New("unexpected IP")
	}
	return tx.inserted, nil
}

// CountFailures returns the configured failure count.
func (tx *fakeTx) CountFailures(_ context.Context, _ string, _ time.Time) (int, error) {
	return tx.count, nil
}

// Block records that ingestion requested a block.
func (tx *fakeTx) Block(_ context.Context, _ string, _ time.Time, _ time.Time) (*decisions.Decision, error) {
	tx.blocked = true
	if tx.unchanged {
		return nil, nil
	}
	return &decisions.Decision{ID: "decision", State: decisions.StateBanned}, nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing repository", func(t *testing.T) {
		t.Parallel()

		_, err := ingestion.New(nil, detection.Rule{
			Threshold: 1,
			Window:    time.Minute,
			Ban:       time.Minute,
		})

		require.ErrorContains(t, err, "repository")
	})

	t.Run("rejects invalid rule", func(t *testing.T) {
		t.Parallel()

		_, err := ingestion.New(&fakeRepository{}, detection.Rule{})

		require.ErrorContains(t, err, "threshold")
	})
}

// validEvent returns a representative, timestamped Snitch event.
func validEvent() events.Envelope {
	return events.Envelope{
		Version:   1,
		ID:        "a",
		Source:    "keycloak",
		Kind:      "LOGIN_ERROR",
		IP:        "203.0.113.5",
		Timestamp: time.Now(),
	}
}

// processEvent isolates the repository and policy for each independently parallel subtest.
func processEvent(t *testing.T, event events.Envelope, count int, inserted bool) (*decisions.Decision, *fakeRepository, *fakeTx, error) {
	t.Helper()
	tx := &fakeTx{inserted: inserted, count: count}
	repo := &fakeRepository{tx: tx}
	service, err := ingestion.New(repo, detection.Rule{
		Threshold: 5,
		Window:    time.Minute,
		Ban:       15 * time.Minute,
	})

	require.NoError(t, err)
	result, err := service.Process(t.Context(), event, time.Now())
	return result.Decision, repo, tx, err
}

func TestServiceProcess(t *testing.T) {
	t.Parallel()

	t.Run("threshold reached", func(t *testing.T) {
		t.Parallel()

		decision, repo, tx, err := processEvent(t, validEvent(), 5, true)

		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.Equal(t, 1, repo.calls)
		assert.True(t, tx.blocked)
	})

	t.Run("below threshold", func(t *testing.T) {
		t.Parallel()

		decision, repo, tx, err := processEvent(t, validEvent(), 4, true)

		require.NoError(t, err)
		assert.Nil(t, decision)
		assert.Equal(t, 1, repo.calls)
		assert.False(t, tx.blocked)
	})

	t.Run("duplicate event", func(t *testing.T) {
		t.Parallel()

		decision, repo, tx, err := processEvent(t, validEvent(), 5, false)

		require.NoError(t, err)
		assert.Nil(t, decision)
		assert.Equal(t, 1, repo.calls)
		assert.False(t, tx.blocked)
	})

	t.Run("invalid IP", func(t *testing.T) {
		t.Parallel()

		event := validEvent()
		event.IP = "bad"
		decision, repo, tx, err := processEvent(t, event, 0, true)

		require.ErrorIs(t, err, ingestion.ErrInvalidEvent)
		assert.Nil(t, decision)
		assert.Zero(t, repo.calls)
		assert.False(t, tx.blocked)
	})

	t.Run("unsupported schema", func(t *testing.T) {
		t.Parallel()

		event := validEvent()
		event.Version = 2
		decision, repo, tx, err := processEvent(t, event, 0, true)

		require.ErrorIs(t, err, ingestion.ErrInvalidEvent)
		assert.Nil(t, decision)
		assert.Zero(t, repo.calls)
		assert.False(t, tx.blocked)
	})

	t.Run("missing IP is ignored", func(t *testing.T) {
		t.Parallel()

		event := validEvent()
		event.IP = ""
		decision, repo, tx, err := processEvent(t, event, 0, true)

		require.NoError(t, err)
		assert.Nil(t, decision)
		assert.Zero(t, repo.calls)
		assert.False(t, tx.blocked)
	})

	t.Run("successful login is ignored", func(t *testing.T) {
		t.Parallel()

		event := validEvent()
		event.Kind = "LOGIN"
		decision, repo, tx, err := processEvent(t, event, 0, true)

		require.NoError(t, err)
		assert.Nil(t, decision)
		assert.Zero(t, repo.calls)
		assert.False(t, tx.blocked)
	})
}

// TestProcessingOutcomes distinguishes every non-error detection path for diagnostic logging.
func TestProcessingOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		kind      string
		ip        string
		inserted  bool
		count     int
		unchanged bool
		outcome   ingestion.Outcome
		reason    string
	}{
		{name: "ignored event type", kind: "LOGIN", ip: "203.0.113.5", outcome: ingestion.OutcomeIgnored, reason: "unsupported_event_type"},
		{name: "missing address", kind: "LOGIN_ERROR", outcome: ingestion.OutcomeIgnored, reason: "missing_ip"},
		{name: "duplicate", kind: "LOGIN_ERROR", ip: "203.0.113.5", outcome: ingestion.OutcomeDuplicate},
		{name: "below threshold", kind: "LOGIN_ERROR", ip: "203.0.113.5", inserted: true, count: 4, outcome: ingestion.OutcomeBelowThreshold},
		{name: "threshold met", kind: "LOGIN_ERROR", ip: "203.0.113.5", inserted: true, count: 5, outcome: ingestion.OutcomeUpdated},
		{name: "unchanged decision", kind: "LOGIN_ERROR", ip: "203.0.113.5", inserted: true, count: 5, unchanged: true, outcome: ingestion.OutcomeUnchanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tx := &fakeTx{inserted: tt.inserted, count: tt.count, unchanged: tt.unchanged}
			repo := &fakeRepository{tx: tx}
			service, err := ingestion.New(repo, detection.Rule{Threshold: 5, Window: time.Minute, Ban: 15 * time.Minute})
			require.NoError(t, err)
			event := validEvent()
			event.Kind = tt.kind
			event.IP = tt.ip
			result, err := service.Process(t.Context(), event, time.Now())
			require.NoError(t, err)
			assert.Equal(t, tt.outcome, result.Outcome)
			assert.Equal(t, tt.reason, result.Reason)
			if tt.outcome == ingestion.OutcomeUpdated {
				require.NotNil(t, result.Decision)
			} else {
				assert.Nil(t, result.Decision)
			}
			if tt.outcome == ingestion.OutcomeBelowThreshold || tt.outcome == ingestion.OutcomeUpdated || tt.outcome == ingestion.OutcomeUnchanged {
				assert.Equal(t, tt.count, result.Failures)
				assert.Equal(t, 5, result.Threshold)
			}
		})
	}
}
