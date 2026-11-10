package bans_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// fakeStore records the manual-ban storage calls made by AdminService.
type fakeStore struct {
	// ip captures the address passed to the fake store.
	ip string
	// until captures the requested expiry passed to the fake store.
	until time.Time
	// reason captures the operator reason passed to the fake store.
	reason string
	// id captures the decision ID passed to the fake store.
	id string
}

// ApplyManualBan records the manual-ban inputs for assertions.
func (r *fakeStore) ApplyManualBan(_ context.Context, ip string, until time.Time, reason string, _ time.Time) (bans.Record, error) {
	r.ip, r.until, r.reason = ip, until, reason
	return bans.Record{}, nil
}

// ReleaseAllSources records the decision ID selected for release.
func (r *fakeStore) ReleaseAllSources(_ context.Context, id string, _ time.Time) (bans.Record, error) {
	r.id = id
	return bans.Record{}, nil
}

// ListActive returns the fake store’s active ban view.
func (r *fakeStore) ListActive(context.Context, time.Time) ([]bans.Record, error) { return nil, nil }

// GetDecision records the requested decision ID.
func (r *fakeStore) GetDecision(_ context.Context, id string, _ time.Time) (bans.Record, error) {
	r.id = id
	return bans.Record{}, nil
}

func TestNewAdminService(t *testing.T) {
	t.Parallel()

	t.Run("accepts store", func(t *testing.T) {
		t.Parallel()

		service, err := bans.NewAdminService(&fakeStore{})

		require.NoError(t, err)
		assert.NotNil(t, service)
	})

	t.Run("rejects missing store", func(t *testing.T) {
		t.Parallel()

		_, err := bans.NewAdminService(nil)

		require.ErrorContains(t, err, "store")
	})
}

func TestAdminServiceBanManual(t *testing.T) {
	t.Parallel()

	invalid := func(t *testing.T, request bans.ManualBanRequest) {
		t.Helper()
		store := &fakeStore{}
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		_, err = service.BanManual(t.Context(), request, time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
		assert.Empty(t, store.ip)
	}
	t.Run("rejects invalid address", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{IP: "not-an-address", Duration: time.Hour, Reason: "incident"})
	})

	t.Run("rejects unspecified address", func(t *testing.T) {
		t.Parallel()

		invalid(t, bans.ManualBanRequest{IP: "0.0.0.0", Duration: time.Hour, Reason: "incident"})
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

		invalid(t, bans.ManualBanRequest{IP: "203.0.113.1", Duration: 31 * 24 * time.Hour, Reason: "incident"})
	})

	t.Run("canonicalizes IPv4-mapped address and trims reason", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		now := time.Now()
		_, err = service.BanManual(t.Context(), bans.ManualBanRequest{IP: "::ffff:203.0.113.1", Duration: time.Hour, Reason: " incident "}, now)

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

		service, err := bans.NewAdminService(&fakeStore{})

		require.NoError(t, err)
		_, err = service.Release(t.Context(), " ", time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
	})

	t.Run("delegates valid decision ID", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store)

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

		service, err := bans.NewAdminService(&fakeStore{})

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

		service, err := bans.NewAdminService(&fakeStore{})

		require.NoError(t, err)
		_, err = service.GetDecision(t.Context(), " ", time.Now())

		require.ErrorIs(t, err, bans.ErrInvalid)
	})

	t.Run("delegates valid decision ID", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		_, err = service.GetDecision(t.Context(), "decision-one", time.Now())

		require.NoError(t, err)
		assert.Equal(t, "decision-one", store.id)
	})
}
