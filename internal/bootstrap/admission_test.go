package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// admissionState supplies persisted facts without opening provider connections.
type admissionState struct {
	// managed identifies outstanding destination obligations.
	managed []string
	// active contains the currently effective bans.
	active []model.Record
}

// ManagedTargets reports outstanding destination obligations.
func (s admissionState) ManagedTargets(context.Context) ([]string, error) { return s.managed, nil }

// ListActive reports currently effective bans.
func (s admissionState) ListActive(context.Context, time.Time) ([]model.Record, error) {
	return s.active, nil
}

func TestValidateAdmission(t *testing.T) {
	t.Parallel()

	t.Run("observe-only refuses unresolved destination work", func(t *testing.T) {
		t.Parallel()
		state := admissionState{managed: []string{"cloudflare.edge"}}
		require.ErrorContains(t, ValidateAdmission(t.Context(), state, bans.Policy{ObserveOnly: true}, time.Now()), "reconciled first")
	})

	t.Run("observe-only accepts a clean enforcement store", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, ValidateAdmission(t.Context(), admissionState{}, bans.Policy{ObserveOnly: true}, time.Now()))
	})

	t.Run("new protection refuses a matching existing active ban", func(t *testing.T) {
		t.Parallel()
		protection, err := bans.NewProtection([]string{"203.0.113.0/24"})
		require.NoError(t, err)
		state := admissionState{active: []model.Record{{Decision: model.Decision{IP: "203.0.113.9"}}}}
		require.ErrorContains(t, ValidateAdmission(t.Context(), state, bans.Policy{Protection: protection}, time.Now()), "release and reconcile existing ban")
	})

	t.Run("unrelated active bans do not prevent protection", func(t *testing.T) {
		t.Parallel()
		protection, err := bans.NewProtection([]string{"203.0.113.0/24"})
		require.NoError(t, err)
		state := admissionState{active: []model.Record{{Decision: model.Decision{IP: "192.0.2.9"}}}}
		require.NoError(t, ValidateAdmission(t.Context(), state, bans.Policy{Protection: protection}, time.Now()))
	})
}
