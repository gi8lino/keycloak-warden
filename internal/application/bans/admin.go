// Package bans defines ban source policy and administrative ban operations.
package bans

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
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
	// ErrNotFound identifies a missing decision or a ban that is no longer active for release.
	ErrNotFound = errors.New("active ban not found")
)

// Store atomically applies administrative changes and reads effective ban decisions.
type Store interface {
	// ApplyManualBan adds or extends the manual source without affecting automatic sources.
	ApplyManualBan(context.Context, string, time.Time, string, time.Time) (Record, error)
	// ReleaseAllSources clears automatic and manual sources and resets the observation generation.
	ReleaseAllSources(context.Context, string, time.Time) (Record, error)
	// ListActive returns currently effective blocks.
	ListActive(context.Context, time.Time) ([]Record, error)
	// GetDecision returns the decision, including released historical decisions.
	GetDecision(context.Context, string, time.Time) (Record, error)
}

// AdminService coordinates validated administrative ban operations independently of HTTP and SQLite.
type AdminService struct {
	// store provides transactional persistence for administrative operations.
	store Store
}

// NewAdminService constructs the administrative ban service.
func NewAdminService(store Store) (*AdminService, error) {
	if store == nil {
		return nil, errors.New("ban store is required")
	}
	return &AdminService{store: store}, nil
}

// BanManual validates the request and adds or extends only its manual source.
func (s *AdminService) BanManual(ctx context.Context, request ManualBanRequest, now time.Time) (Record, error) {
	ip, reason, err := validateManualBanRequest(request)
	if err != nil {
		return Record{}, err
	}

	return s.store.ApplyManualBan(ctx, ip, now.Add(request.Duration), reason, now)
}

// validateManualBanRequest validates and normalizes a manual ban request.
func validateManualBanRequest(request ManualBanRequest) (string, string, error) {
	ip, err := ipaddress.ParseUnicast(strings.TrimSpace(request.IP))
	if err != nil {
		return "", "", fmt.Errorf("%w: ipAddress must be a single unicast address", ErrInvalid)
	}

	if !validDuration(request.Duration, MinDuration, MaxDuration) {
		return "", "", fmt.Errorf("%w: duration must be between %s and %s", ErrInvalid, MinDuration, MaxDuration)
	}

	reason := strings.TrimSpace(request.Reason)
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
func (s *AdminService) Release(ctx context.Context, id string, now time.Time) (Record, error) {
	if strings.TrimSpace(id) == "" {
		return Record{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}

	return s.store.ReleaseAllSources(ctx, id, now)
}

// ListActive returns effective blocks with their automatic and manual sources.
func (s *AdminService) ListActive(ctx context.Context, now time.Time) ([]Record, error) {
	return s.store.ListActive(ctx, now)
}

// GetDecision returns the decision and sources identified by a stable decision ID.
func (s *AdminService) GetDecision(ctx context.Context, id string, now time.Time) (Record, error) {
	if strings.TrimSpace(id) == "" {
		return Record{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}

	return s.store.GetDecision(ctx, id, now)
}
