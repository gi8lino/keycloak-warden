package bans_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// fakeStore implements an in-memory transaction for administration service tests.
type fakeStore struct {
	// historyCursor records the page selected for a decision read.
	historyPage int
	ip          string
	until       time.Time
	reason      string
	id          string
	targets     []string
	released    bool
}

// TransactDecision executes one application workflow on the fake transaction.
func (r *fakeStore) TransactDecision(ctx context.Context, apply func(bans.MutationTransaction) error) error {
	return apply(r)
}

// EnsureDecision records the canonical address used by the workflow.
func (r *fakeStore) EnsureDecision(_ context.Context, ip string) error {
	r.ip = ip
	return nil
}

// Source returns no previously stored source.
func (r *fakeStore) Source(context.Context, string, bans.SourceKind) (bans.Source, bool, error) {
	return bans.Source{}, false, nil
}

// PutSource records an application-validated manual reason.
func (r *fakeStore) PutSource(_ context.Context, ip string, source bans.Source) error {
	r.ip = ip
	r.until = source.ExpiresAt
	r.reason = source.Reason
	return nil
}

// Decision returns a stable current decision for the requested IP.
func (r *fakeStore) Decision(_ context.Context, ip string) (decisions.Decision, error) {
	return decisions.Decision{ID: "decision-one", IP: ip, State: decisionstate.StateUnbanned}, nil
}

// Sources returns the previously recorded manual source unless it was cleared.
func (r *fakeStore) Sources(context.Context, string, time.Time) ([]bans.Source, error) {
	if r.released || r.until.IsZero() {
		return nil, nil
	}
	return []bans.Source{{Kind: bans.SourceManual, ExpiresAt: r.until, Reason: r.reason}}, nil
}

// SaveDecision records the target names supplied to the transaction.
func (r *fakeStore) SaveDecision(_ context.Context, _, _ decisions.Decision, _ bool, targets []string) error {
	r.targets = append([]string(nil), targets...)
	return nil
}

// DecisionByID returns an active decision eligible for manual release.
func (r *fakeStore) DecisionByID(_ context.Context, id string) (decisions.Decision, error) {
	r.id = id
	return decisions.Decision{
		ID: id, IP: "203.0.113.1", State: decisionstate.StateBanned,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

// DeleteSources records removal of the independent ban reasons.
func (r *fakeStore) DeleteSources(context.Context, string) error {
	r.released = true
	return nil
}

// ResetFailures simulates advancing the observation generation.
func (r *fakeStore) ResetFailures(context.Context, string) error { return nil }

// ExpiredSourceIPs returns no elapsed sources for administration tests.
func (r *fakeStore) ExpiredSourceIPs(context.Context, time.Time) ([]string, error) {
	return nil, nil
}

// DeleteExpiredSources is unused by administrative operations.
func (r *fakeStore) DeleteExpiredSources(context.Context, time.Time) error { return nil }

// Record returns the fake persisted ban view.
func (r *fakeStore) Record(context.Context, string, time.Time) (bans.Record, error) {
	return bans.Record{}, nil
}

// ListActive returns the fake store's active ban view.
func (r *fakeStore) ListActive(context.Context, time.Time) ([]bans.Record, error) {
	return nil, nil
}

// GetDecision records a requested stable decision ID.
func (r *fakeStore) GetDecision(_ context.Context, id string, _ time.Time) (bans.Record, error) {
	r.id = id
	return bans.Record{}, nil
}

func TestNewAdminService(t *testing.T) {
	t.Parallel()

	t.Run("accepts store", func(t *testing.T) {
		t.Parallel()

		service, err := bans.NewAdminService(&fakeStore{}, nil)

		require.NoError(t, err)
		assert.NotNil(t, service)
	})

	t.Run("rejects missing store", func(t *testing.T) {
		t.Parallel()

		_, err := bans.NewAdminService(nil, nil)

		require.ErrorContains(t, err, "store")
	})
}

func TestAdminServiceBanManual(t *testing.T) {
	t.Parallel()

	invalid := func(t *testing.T, request bans.ManualBanRequest) {
		t.Helper()
		store := &fakeStore{}
		service, err := bans.NewAdminService(store, nil)

		require.NoError(t, err)
		_, err = service.BanManual(t.Context(), request, time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
		assert.Empty(t, store.ip)
	}

	t.Run("rejects invalid address", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{
			IP:       "not-an-address",
			Duration: time.Hour,
			Reason:   "incident",
		})
	})

	t.Run("rejects unspecified address", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{
			IP:       "0.0.0.0",
			Duration: time.Hour,
			Reason:   "incident",
		})
	})

	t.Run("rejects missing reason", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{IP: "203.0.113.1", Duration: time.Hour})
	})

	t.Run("rejects zero duration", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{IP: "203.0.113.1", Reason: "incident"})
	})

	t.Run("rejects duration above maximum", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{
			IP:       "203.0.113.1",
			Duration: 31 * 24 * time.Hour,
			Reason:   "incident",
		})
	})

	t.Run("canonicalizes IPv4-mapped address and trims reason", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store, nil)

		require.NoError(t, err)
		now := time.Now()
		_, err = service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "::ffff:203.0.113.1",
			Duration: time.Hour,
			Reason:   " incident ",
		}, now)

		require.NoError(t, err)
		assert.Equal(t, "203.0.113.1", store.ip)
		assert.Equal(t, now.Add(time.Hour), store.until)
		assert.Equal(t, "incident", store.reason)
	})
}

func TestAdminServiceRelease(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing decision ID", func(t *testing.T) {
		t.Parallel()

		service, err := bans.NewAdminService(&fakeStore{}, nil)

		require.NoError(t, err)
		_, err = service.Release(t.Context(), " ", time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
	})

	t.Run("delegates valid decision ID", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store, nil)

		require.NoError(t, err)
		_, err = service.Release(t.Context(), "decision-one", time.Now())

		require.NoError(t, err)
		assert.Equal(t, "decision-one", store.id)
	})
}

func TestAdminServiceListActive(t *testing.T) {
	t.Parallel()

	t.Run("delegates to store", func(t *testing.T) {
		t.Parallel()

		service, err := bans.NewAdminService(&fakeStore{}, nil)

		require.NoError(t, err)
		views, err := service.ListActive(t.Context(), time.Now())

		require.NoError(t, err)
		assert.Empty(t, views)
	})
}

func TestAdminServiceGetDecision(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing decision ID", func(t *testing.T) {
		t.Parallel()

		service, err := bans.NewAdminService(&fakeStore{}, nil)

		require.NoError(t, err)
		_, err = service.GetDecision(t.Context(), " ", time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
	})

	t.Run("delegates valid decision ID", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store, nil)

		require.NoError(t, err)
		_, err = service.GetDecision(t.Context(), "decision-one", time.Now())

		require.NoError(t, err)
		assert.Equal(t, "decision-one", store.id)
	})
}

func TestAdminServiceTargets(t *testing.T) {
	t.Parallel()

	t.Run("manual bans receive the configured destination names", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		targets := []string{"cloudflare.edge", "webhook.slack"}
		service, err := bans.NewAdminService(store, targets)
		require.NoError(t, err)

		targets[0] = "modified"
		_, err = service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "203.0.113.1",
			Duration: time.Hour,
			Reason:   "investigation",
		}, time.Now())

		require.NoError(t, err)
		assert.Equal(t, []string{"cloudflare.edge", "webhook.slack"}, store.targets)
	})

	t.Run("manual releases receive the configured destination names", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store, []string{"webhook.slack"})
		require.NoError(t, err)

		_, err = service.Release(t.Context(), "decision-one", time.Now())

		require.NoError(t, err)
		assert.Equal(t, []string{"webhook.slack"}, store.targets)
	})
}

// GetDecisionPage records the one-based page forwarded to persistence.
func (r *fakeStore) GetDecisionPage(_ context.Context, id string, _ time.Time, page int) (bans.Record, error) {
	r.id = id
	r.historyPage = page
	return bans.Record{}, nil
}

func TestAdminServiceGetDecisionPage(t *testing.T) {
	t.Parallel()

	t.Run("passes page 100 to persistence", func(t *testing.T) {
		t.Parallel()
		store := &fakeStore{}
		service, err := bans.NewAdminService(store, nil)
		require.NoError(t, err)

		_, err = service.GetDecisionPage(t.Context(), "one", time.Now(), 100)
		require.NoError(t, err)
		assert.Equal(t, 100, store.historyPage)
		assert.Equal(t, "one", store.id)
	})

	t.Run("rejects an invalid page before persistence", func(t *testing.T) {
		t.Parallel()
		store := &fakeStore{}
		service, err := bans.NewAdminService(store, nil)
		require.NoError(t, err)

		_, err = service.GetDecisionPage(t.Context(), "one", time.Now(), 0)
		require.ErrorIs(t, err, bans.ErrInvalid)
		assert.Empty(t, store.id)
	})
}
