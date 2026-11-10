// Package bans owns manual ban management independently of HTTP and storage.
package bans

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
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

// SourceKind distinguishes independent reasons for an effective block.
type SourceKind string

const (
	// SourceAutomatic represents the failed-login detection rule.
	SourceAutomatic SourceKind = "automatic"
	// SourceManual represents an operator-requested ban.
	SourceManual SourceKind = "manual"
)

// Source describes one active reason to block an IP address.
type Source struct {
	// Kind identifies the automatic or manual source of a block.
	Kind SourceKind `json:"kind"`
	// ExpiresAt is the UTC deadline for this source.
	ExpiresAt time.Time `json:"expiresAt"`
	// Reason records the operator explanation for the requested block.
	Reason string `json:"reason,omitempty"`
}

// Ban is the effective decision together with its independent sources and delivery state.
type Ban struct {
	// Decision contains the effective desired state for the address.
	Decision decisions.Decision `json:"decision"`
	// Sources contains the independent active reasons for the block.
	Sources []Source `json:"sources"`
	// Deliveries records each destination’s acknowledged revision.
	Deliveries []decisions.Acknowledgement `json:"deliveries"`
}

// Request specifies a new or extended manual block.
type Request struct {
	// IP is the reported client address, which may be absent in an event.
	IP string
	// Duration specifies how long the requested manual block should last.
	Duration time.Duration
	// Reason records the operator explanation for the requested block.
	Reason string
}

// Repository atomically stores operator changes and reads effective ban decisions.
type Repository interface {
	// ApplyManualBan adds or extends the manual source without affecting automatic sources.
	ApplyManualBan(context.Context, string, time.Time, string, time.Time) (Ban, error)
	// ReleaseAllSources clears automatic and manual sources and resets failure counting.
	ReleaseAllSources(context.Context, string, time.Time) (Ban, error)
	// ListActive returns currently effective blocks.
	ListActive(context.Context, time.Time) ([]Ban, error)
	// GetDecision returns the decision, including released historical decisions.
	GetDecision(context.Context, string, time.Time) (Ban, error)
}

// Service coordinates validated manual bans without depending on SQLite or HTTP.
type Service struct {
	// repository provides transactional persistence for this application service.
	repository Repository
}

// New constructs the manual ban application service.
func New(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("manual ban repository is required")
	}
	return &Service{repository: repository}, nil
}

// Ban validates the request, normalizes its address and extends its manual source.
func (s *Service) Ban(ctx context.Context, request Request, now time.Time) (Ban, error) {
	ip, reason, err := validateBanRequest(request)
	if err != nil {
		return Ban{}, err
	}

	return s.repository.ApplyManualBan(ctx, ip, now.Add(request.Duration), reason, now)
}

// validateBanRequest validates and normalizes a manual ban request.
func validateBanRequest(request Request) (string, string, error) {
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

// Unban clears every active source and resets detection for the specified decision.
func (s *Service) Unban(ctx context.Context, id string, now time.Time) (Ban, error) {
	if strings.TrimSpace(id) == "" {
		return Ban{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}

	return s.repository.ReleaseAllSources(ctx, id, now)
}

// List returns current effective blocks, including automatic and manual sources.
func (s *Service) List(ctx context.Context, now time.Time) ([]Ban, error) {
	return s.repository.ListActive(ctx, now)
}

// Get returns the effective decision and sources identified by a stable decision ID.
func (s *Service) Get(ctx context.Context, id string, now time.Time) (Ban, error) {
	if strings.TrimSpace(id) == "" {
		return Ban{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}

	return s.repository.GetDecision(ctx, id, now)
}
