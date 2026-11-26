package ingestion_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// fakeRepository captures ingestion transactions for service tests.
type fakeRepository struct {
	// calls counts calls made to the fake repository.
	calls int
	// tx supplies the fake transaction used by the repository.
	tx *fakeTx
	// commitErr simulates a failure after a successful transaction callback.
	commitErr error
}

// TransactObservation runs the application callback with the fake transaction.
func (r *fakeRepository) TransactObservation(_ context.Context, apply func(ingestion.Transaction) error) error {
	r.calls++
	if err := apply(r.tx); err != nil {
		return err
	}
	return r.commitErr
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
	// targets records destinations passed to the transaction.
	targets []string
	// until captures the requested automatic ban expiry.
	until time.Time
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

// RecordObservation accepts hypothetical threshold hits in tests.
func (tx *fakeTx) RecordObservation(context.Context, ingestion.Observation) error { return nil }

// EnsureDecision records that ingestion requested an automatic source.
func (tx *fakeTx) EnsureDecision(context.Context, string) error {
	tx.blocked = true
	return nil
}

// Source reports that the automatic source is not yet stored.
func (tx *fakeTx) Source(context.Context, string, bans.SourceKind) (bans.Source, bool, error) {
	return bans.Source{}, false, nil
}

// PutSource records the source selected by the detection policy.
func (tx *fakeTx) PutSource(_ context.Context, _ string, source bans.Source) error {
	tx.until = source.ExpiresAt
	return nil
}

// Decision returns the desired state before applying this observation.
func (tx *fakeTx) Decision(_ context.Context, ip string) (decisions.Decision, error) {
	if tx.unchanged {
		return decisions.Decision{
			ID: "decision", IP: ip, State: decisionstate.StateBanned,
			ExpiresAt: tx.until,
		}, nil
	}
	return decisions.Decision{ID: "decision", IP: ip, State: decisionstate.StateUnbanned}, nil
}

// Sources exposes the new automatic source to application reconciliation.
func (tx *fakeTx) Sources(context.Context, string, time.Time) ([]bans.Source, error) {
	return []bans.Source{{Kind: bans.SourceAutomatic, ExpiresAt: tx.until}}, nil
}

// SaveDecision records destination identifiers from the application.
func (tx *fakeTx) SaveDecision(_ context.Context, _, _ decisions.Decision, _ []bans.Source, _ bans.ChangeCause, _ bool, targets []string) error {
	tx.targets = append([]string(nil), targets...)
	return nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing repository", func(t *testing.T) {
		t.Parallel()

		_, err := ingestion.New(nil, detection.Rule{
			Threshold: 1,
			Window:    time.Minute,
			Ban:       time.Minute,
		}, nil)

		require.ErrorContains(t, err, "repository")
	})

	t.Run("rejects invalid rule", func(t *testing.T) {
		t.Parallel()

		_, err := ingestion.New(&fakeRepository{}, detection.Rule{}, nil)

		require.ErrorContains(t, err, "threshold")
	})
}

// validEvent returns a representative, timestamped Snitch event.
func validEvent() events.Envelope {
	return events.Envelope{
		Version:   events.SchemaVersion,
		ID:        "a",
		Source:    events.SourceKeycloak,
		Kind:      events.KindLoginError,
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
	}, nil)

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
		event.Version = events.SchemaVersion + 1
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

// assertProcessingOutcome checks one independent processing path.
func assertProcessingOutcome(t *testing.T, kind, ip string, inserted bool, count int, unchanged bool, outcome ingestion.Outcome, reason string) {
	t.Helper()

	tx := &fakeTx{
		inserted:  inserted,
		count:     count,
		unchanged: unchanged,
	}
	repo := &fakeRepository{tx: tx}
	service, err := ingestion.New(repo, detection.Rule{
		Threshold: 5,
		Window:    time.Minute,
		Ban:       15 * time.Minute,
	}, nil)
	require.NoError(t, err)

	event := validEvent()
	event.Kind = kind
	event.IP = ip
	result, err := service.Process(t.Context(), event, time.Now())

	require.NoError(t, err)
	assert.Equal(t, outcome, result.Outcome)
	assert.Equal(t, reason, result.Reason)
	if outcome == ingestion.OutcomeUpdated {
		require.NotNil(t, result.Decision)
	} else {
		assert.Nil(t, result.Decision)
	}
	if outcome == ingestion.OutcomeBelowThreshold || outcome == ingestion.OutcomeUpdated || outcome == ingestion.OutcomeUnchanged {
		assert.Equal(t, count, result.Failures)
		assert.Equal(t, 5, result.Threshold)
	}
}

// TestProcessingOutcomes distinguishes detection paths for diagnostic logging.
func TestProcessingOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("ignored event type", func(t *testing.T) {
		t.Parallel()

		assertProcessingOutcome(t, "LOGIN", "203.0.113.5", false, 0, false, ingestion.OutcomeIgnored, "unsupported_event_type")
	})

	t.Run("missing address", func(t *testing.T) {
		t.Parallel()

		assertProcessingOutcome(t, events.KindLoginError, "", false, 0, false, ingestion.OutcomeIgnored, "missing_ip")
	})

	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()

		assertProcessingOutcome(t, events.KindLoginError, "203.0.113.5", false, 0, false, ingestion.OutcomeDuplicate, "")
	})

	t.Run("below threshold", func(t *testing.T) {
		t.Parallel()

		assertProcessingOutcome(t, events.KindLoginError, "203.0.113.5", true, 4, false, ingestion.OutcomeBelowThreshold, "")
	})

	t.Run("threshold met", func(t *testing.T) {
		t.Parallel()

		assertProcessingOutcome(t, events.KindLoginError, "203.0.113.5", true, 5, false, ingestion.OutcomeUpdated, "")
	})

	t.Run("unchanged decision", func(t *testing.T) {
		t.Parallel()

		assertProcessingOutcome(t, events.KindLoginError, "203.0.113.5", true, 5, true, ingestion.OutcomeUnchanged, "")
	})
}

func TestServicePassesTargetsToStorage(t *testing.T) {
	t.Parallel()

	t.Run("uses an immutable copy of destination names", func(t *testing.T) {
		t.Parallel()

		tx := &fakeTx{inserted: true, count: 1}
		repo := &fakeRepository{tx: tx}
		targets := []string{"cloudflare.edge", "webhook.slack"}
		service, err := ingestion.New(repo, detection.Rule{
			Threshold: 1,
			Window:    time.Minute,
			Ban:       15 * time.Minute,
		}, targets)
		require.NoError(t, err)

		targets[0] = "modified"
		_, err = service.Process(t.Context(), validEvent(), time.Now())

		require.NoError(t, err)
		assert.Equal(t, []string{"cloudflare.edge", "webhook.slack"}, tx.targets)
	})
}

func TestServiceProcessCommitFailure(t *testing.T) {
	t.Parallel()

	t.Run("does not publish a revised decision before commit", func(t *testing.T) {
		t.Parallel()

		tx := &fakeTx{inserted: true, count: 5}
		repository := &fakeRepository{tx: tx, commitErr: errors.New("commit failed")}
		service, err := ingestion.New(repository, detection.Rule{
			Threshold: 5,
			Window:    time.Minute,
			Ban:       time.Minute,
		}, []string{"edge"})
		require.NoError(t, err)

		result, err := service.Process(t.Context(), validEvent(), time.Now())

		require.ErrorContains(t, err, "commit failed")
		assert.Equal(t, ingestion.Result{}, result)
		assert.Equal(t, 1, repository.calls)
		assert.Equal(t, []string{"edge"}, tx.targets)
	})
}

// TestProtectedEvents verifies that exempt login failures never reach storage.
func TestProtectedEvents(t *testing.T) {
	t.Parallel()

	t.Run("protected address skips storage before threshold", func(t *testing.T) {
		t.Parallel()

		protection, err := bans.NewProtection([]string{"203.0.113.5"})
		require.NoError(t, err)

		repo := &fakeRepository{tx: &fakeTx{inserted: true, count: 1}}
		service, err := ingestion.NewWithPolicy(repo, detection.Rule{
			Threshold: 5,
			Window:    time.Minute,
			Ban:       15 * time.Minute,
		}, nil, bans.Policy{Protection: protection})
		require.NoError(t, err)

		result, err := service.Process(t.Context(), validEvent(), time.Now())

		require.NoError(t, err)
		assert.Equal(t, ingestion.Result{
			Outcome: ingestion.OutcomeProtected,
			IP:      "203.0.113.5",
		}, result)
		assert.Zero(t, repo.calls)
	})

	t.Run("mapped address in protected CIDR skips observe-only storage", func(t *testing.T) {
		t.Parallel()

		protection, err := bans.NewProtection([]string{"203.0.113.0/24"})
		require.NoError(t, err)

		repo := &fakeRepository{tx: &fakeTx{inserted: true, count: 5}}
		service, err := ingestion.NewWithPolicy(repo, detection.Rule{
			Threshold: 5,
			Window:    time.Minute,
			Ban:       15 * time.Minute,
		}, nil, bans.Policy{
			Protection:  protection,
			ObserveOnly: true,
		})
		require.NoError(t, err)

		event := validEvent()
		event.IP = "::ffff:203.0.113.5"
		result, err := service.Process(t.Context(), event, time.Now())

		require.NoError(t, err)
		assert.Equal(t, ingestion.Result{
			Outcome: ingestion.OutcomeProtected,
			IP:      "203.0.113.5",
		}, result)
		assert.Zero(t, repo.calls)
	})

	t.Run("unprotected address still enters detection", func(t *testing.T) {
		t.Parallel()

		protection, err := bans.NewProtection([]string{"198.51.100.0/24"})
		require.NoError(t, err)

		repo := &fakeRepository{tx: &fakeTx{inserted: true, count: 4}}
		service, err := ingestion.NewWithPolicy(repo, detection.Rule{
			Threshold: 5,
			Window:    time.Minute,
			Ban:       15 * time.Minute,
		}, nil, bans.Policy{Protection: protection})
		require.NoError(t, err)

		result, err := service.Process(t.Context(), validEvent(), time.Now())

		require.NoError(t, err)
		assert.Equal(t, ingestion.Result{
			Outcome:   ingestion.OutcomeBelowThreshold,
			IP:        "203.0.113.5",
			Failures:  4,
			Threshold: 5,
		}, result)
		assert.Equal(t, 1, repo.calls)
	})
}
