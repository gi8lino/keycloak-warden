// Package bans defines ban source policy and administrative ban operations.
package bans

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

const (
	// MinDuration is the shortest permitted manually requested ban.
	MinDuration = time.Second
	// MaxDuration prevents accidentally unbounded manual bans.
	MaxDuration = 30 * 24 * time.Hour
	// MaxReasonLength limits the size of persisted operator explanations.
	MaxReasonLength = 512
)

var (
	// ErrInvalid identifies invalid manual ban input.
	ErrInvalid = errors.New("invalid manual ban")
	// ErrProtected identifies a request to ban an exempt address.
	ErrProtected = errors.New("IP address is protected")
	// ErrObserveOnly identifies an enforcement request in observation mode.
	ErrObserveOnly = errors.New("observe-only mode disables manual bans")
	// ErrNotFound identifies a missing decision or a ban that is no longer active for release.
	ErrNotFound = errors.New("active ban not found")
)

// Store provides atomic ban transactions and read-only decision queries.
type Store interface {
	Writer
	// ListActive returns currently effective blocks.
	ListActive(context.Context, time.Time) ([]model.Record, error)
	// GetDecision returns the decision, including released historical decisions.
	GetDecision(context.Context, string, time.Time) (model.Record, error)
	// GetDecisionPage retrieves one bounded, numbered history page.
	GetDecisionPage(context.Context, string, time.Time, HistoryPage) (model.Record, error)
}

// ManualBanRequest specifies a manual ban or extension.
type ManualBanRequest struct {
	// IP identifies the address to ban.
	IP string
	// Duration is the requested ban duration.
	Duration time.Duration
	// Reason describes why the ban was requested.
	Reason string
}

// AdminService manages manual bans and releases.
type AdminService struct {
	// store provides transactional persistence for administrative operations.
	store Store
	// targets identifies the configured destinations for revised decisions.
	targets []string
	// policy controls admission of new bans.
	policy Policy
}

// NewAdminService constructs the administrative ban service.
func NewAdminService(store Store, targets []string) (*AdminService, error) {
	return NewAdminServiceWithPolicy(store, targets, Policy{})
}

// NewAdminServiceWithPolicy constructs administrative operations with ban admission policy.
func NewAdminServiceWithPolicy(store Store, targets []string, policy Policy) (*AdminService, error) {
	if store == nil {
		return nil, errors.New("ban store is required")
	}
	return &AdminService{
		store:   store,
		targets: slices.Clone(targets),
		policy:  policy,
	}, nil
}

// BanManual validates the request and adds or extends only its manual source.
func (s *AdminService) BanManual(ctx context.Context, request ManualBanRequest, now time.Time) (model.Record, error) {
	ip, reason, err := validateManualBanRequest(request)
	if err != nil {
		return model.Record{}, err
	}

	if s.policy.Protection.Contains(netip.MustParseAddr(ip)) {
		return model.Record{}, ErrProtected
	}
	if s.policy.ObserveOnly {
		return model.Record{}, ErrObserveOnly
	}
	return ApplyManualBan(ctx, s.store, ip, now.Add(request.Duration), reason, now, s.targets)
}

// validateManualBanRequest validates and normalizes a manual ban request.
func validateManualBanRequest(request ManualBanRequest) (canonicalIP, reason string, err error) {
	ip, err := ipaddress.ParseUnicast(strings.TrimSpace(request.IP))
	if err != nil {
		return "", "", fmt.Errorf("%w: ipAddress must be a single unicast address", ErrInvalid)
	}

	if !validDuration(request.Duration, MinDuration, MaxDuration) {
		return "", "", fmt.Errorf("%w: duration must be between %s and %s", ErrInvalid, MinDuration, MaxDuration)
	}

	reason = strings.TrimSpace(request.Reason)
	if !validReason(reason, MaxReasonLength) {
		return "", "", fmt.Errorf("%w: reason must contain 1–%d bytes", ErrInvalid, MaxReasonLength)
	}

	return ip.Unmap().String(), reason, nil
}

// validDuration reports whether a duration is within the inclusive bounds.
func validDuration(d, min, max time.Duration) bool {
	return d >= min && d <= max
}

// validReason reports whether a reason has a valid byte length.
func validReason(reason string, max int) bool {
	return len(reason) > 0 && len(reason) <= max
}

// Release clears all active sources and resets detection for the specified decision.
func (s *AdminService) Release(ctx context.Context, id string, now time.Time) (model.Record, error) {
	if strings.TrimSpace(id) == "" {
		return model.Record{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}

	return ReleaseAllSources(ctx, s.store, id, now, s.targets)
}

// ListActive returns effective blocks with their automatic and manual sources.
func (s *AdminService) ListActive(ctx context.Context, now time.Time) ([]model.Record, error) {
	return s.store.ListActive(ctx, now)
}

// GetDecision returns the decision and sources identified by a stable decision ID.
func (s *AdminService) GetDecision(ctx context.Context, id string, now time.Time) (model.Record, error) {
	if strings.TrimSpace(id) == "" {
		return model.Record{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}

	return s.store.GetDecision(ctx, id, now)
}

// GetDecisionPage retrieves a validated page of decision history.
func (s *AdminService) GetDecisionPage(
	ctx context.Context,
	id string,
	now time.Time,
	page int,
	throughRevision int64,
) (model.Record, error) {
	if strings.TrimSpace(id) == "" {
		return model.Record{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}
	bounds, err := NewHistoryPage(page, throughRevision)
	if err != nil {
		return model.Record{}, err
	}
	return s.store.GetDecisionPage(ctx, id, now, bounds)
}
