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
	// ErrNotFound identifies a decision without an active ban.
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

// Repository persists manual sources and reads the effective decisions atomically.
type Repository interface {
	BanManual(context.Context, string, time.Time, string, time.Time) (Ban, error)
	UnbanAll(context.Context, string, time.Time) (Ban, error)
	ListBans(context.Context, time.Time) ([]Ban, error)
	GetBan(context.Context, string, time.Time) (Ban, error)
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
	ip, err := ipaddress.ParseUnicast(strings.TrimSpace(request.IP))
	if err != nil {
		return Ban{}, fmt.Errorf("%w: ipAddress must be a single unicast address", ErrInvalid)
	}
	if request.Duration < MinDuration || request.Duration > MaxDuration {
		return Ban{}, fmt.Errorf("%w: duration must be between %s and %s", ErrInvalid, MinDuration, MaxDuration)
	}
	reason := strings.TrimSpace(request.Reason)
	if reason == "" || len(reason) > MaxReasonLength {
		return Ban{}, fmt.Errorf("%w: reason must contain 1–%d bytes", ErrInvalid, MaxReasonLength)
	}
	return s.repository.BanManual(ctx, ip.Unmap().String(), now.Add(request.Duration), reason, now)
}

// Unban clears every active source and resets detection for the specified decision.
func (s *Service) Unban(ctx context.Context, id string, now time.Time) (Ban, error) {
	if strings.TrimSpace(id) == "" {
		return Ban{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}
	return s.repository.UnbanAll(ctx, id, now)
}

// List returns current effective blocks, including automatic and manual sources.
func (s *Service) List(ctx context.Context, now time.Time) ([]Ban, error) {
	return s.repository.ListBans(ctx, now)
}

// Get returns the effective decision and sources identified by a stable decision ID.
func (s *Service) Get(ctx context.Context, id string, now time.Time) (Ban, error) {
	if strings.TrimSpace(id) == "" {
		return Ban{}, fmt.Errorf("%w: decision ID is required", ErrInvalid)
	}
	return s.repository.GetBan(ctx, id, now)
}
