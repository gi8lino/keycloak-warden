package bans_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// fakeRepo captures manual-ban repository calls for service tests.
type fakeRepo struct {
	// ip captures the address passed to the fake repository.
	ip string
	// until captures the requested expiry passed to the fake repository.
	until time.Time
	// reason captures the operator reason passed to the fake repository.
	reason string
	// id captures the decision ID passed to the fake repository.
	id string
}

// BanManual records the manual-ban inputs for assertions.
func (r *fakeRepo) BanManual(_ context.Context, ip string, until time.Time, reason string, _ time.Time) (bans.Ban, error) {
	r.ip, r.until, r.reason = ip, until, reason
	return bans.Ban{}, nil
}

// UnbanAll records the decision ID selected for release.
func (r *fakeRepo) UnbanAll(_ context.Context, id string, _ time.Time) (bans.Ban, error) {
	r.id = id
	return bans.Ban{}, nil
}

// ListBans returns the fake repository’s active ban view.
func (r *fakeRepo) ListBans(context.Context, time.Time) ([]bans.Ban, error) { return nil, nil }

// GetBan records the requested decision ID.
func (r *fakeRepo) GetBan(_ context.Context, id string, _ time.Time) (bans.Ban, error) {
	r.id = id
	return bans.Ban{}, nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("accepts repository", func(t *testing.T) {
		t.Parallel()

		service, err := bans.New(&fakeRepo{})

		require.NoError(t, err)
		assert.NotNil(t, service)
	})

	t.Run("rejects missing repository", func(t *testing.T) {
		t.Parallel()

		_, err := bans.New(nil)

		require.ErrorContains(t, err, "repository")
	})
}

func TestServiceBan(t *testing.T) {
	t.Parallel()

	invalid := func(t *testing.T, request bans.Request) {
		t.Helper()
		repo := &fakeRepo{}
		service, err := bans.New(repo)

		require.NoError(t, err)
		_, err = service.Ban(t.Context(), request, time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
		assert.Empty(t, repo.ip)
	}
	t.Run("rejects invalid address", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.Request{IP: "not-an-address", Duration: time.Hour, Reason: "incident"})
	})

	t.Run("rejects unspecified address", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.Request{IP: "0.0.0.0", Duration: time.Hour, Reason: "incident"})
	})

	t.Run("rejects missing reason", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.Request{IP: "203.0.113.1", Duration: time.Hour})
	})

	t.Run("rejects zero duration", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.Request{IP: "203.0.113.1", Reason: "incident"})
	})

	t.Run("rejects duration above maximum", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.Request{IP: "203.0.113.1", Duration: 31 * 24 * time.Hour, Reason: "incident"})
	})

	t.Run("canonicalizes IPv4-mapped address and trims reason", func(t *testing.T) {
		t.Parallel()

		repo := &fakeRepo{}
		service, err := bans.New(repo)

		require.NoError(t, err)
		now := time.Now()
		_, err = service.Ban(t.Context(), bans.Request{IP: "::ffff:203.0.113.1", Duration: time.Hour, Reason: " incident "}, now)

		require.NoError(t, err)
		assert.Equal(t, "203.0.113.1", repo.ip)
		assert.Equal(t, now.Add(time.Hour), repo.until)
		assert.Equal(t, "incident", repo.reason)
	})
}

func TestServiceUnban(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing decision ID", func(t *testing.T) {
		t.Parallel()

		service, err := bans.New(&fakeRepo{})

		require.NoError(t, err)
		_, err = service.Unban(t.Context(), " ", time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
	})

	t.Run("delegates valid decision ID", func(t *testing.T) {
		t.Parallel()

		repo := &fakeRepo{}
		service, err := bans.New(repo)

		require.NoError(t, err)
		_, err = service.Unban(t.Context(), "decision-one", time.Now())

		require.NoError(t, err)
		assert.Equal(t, "decision-one", repo.id)
	})
}

func TestServiceList(t *testing.T) {
	t.Parallel()

	t.Run("delegates to repository", func(t *testing.T) {
		t.Parallel()

		service, err := bans.New(&fakeRepo{})

		require.NoError(t, err)
		views, err := service.List(t.Context(), time.Now())

		require.NoError(t, err)
		assert.Empty(t, views)
	})
}

func TestServiceGet(t *testing.T) {
	t.Parallel()

	t.Run("rejects missing decision ID", func(t *testing.T) {
		t.Parallel()

		service, err := bans.New(&fakeRepo{})

		require.NoError(t, err)
		_, err = service.Get(t.Context(), " ", time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
	})

	t.Run("delegates valid decision ID", func(t *testing.T) {
		t.Parallel()

		repo := &fakeRepo{}
		service, err := bans.New(repo)

		require.NoError(t, err)
		_, err = service.Get(t.Context(), "decision-one", time.Now())

		require.NoError(t, err)
		assert.Equal(t, "decision-one", repo.id)
	})
}
