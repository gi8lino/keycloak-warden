package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// AdmissionState describes the persisted enforcement work relevant to startup safety.
type AdmissionState interface {
	// ManagedTargets returns destinations with existing enforcement obligations.
	ManagedTargets(context.Context) ([]string, error)
	// ListActive returns currently effective bans.
	ListActive(context.Context, time.Time) ([]bans.Record, error)
}

// ValidateAdmission refuses a mode or protection change that would abandon existing enforcement.
func ValidateAdmission(ctx context.Context, state AdmissionState, policy bans.Policy, now time.Time) error {
	if policy.ObserveOnly {
		managed, err := state.ManagedTargets(ctx)
		if err != nil {
			return err
		}

		if len(managed) > 0 {
			return errors.New("observe-only requires all existing bans and releases to be reconciled first")
		}
	}

	if !policy.ObserveOnly && policy.Protection.Empty() {
		return nil
	}

	active, err := state.ListActive(ctx, now)
	if err != nil {
		return err
	}

	for _, record := range active {
		address, err := netip.ParseAddr(record.Decision.IP)
		if err != nil {
			return fmt.Errorf("invalid persisted decision IP: %w", err)
		}

		if policy.ObserveOnly || policy.Protection.Contains(address) {
			return fmt.Errorf("release and reconcile existing ban %s before enabling protection or observation mode", record.Decision.IP)
		}
	}
	return nil
}
