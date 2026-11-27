package notifications

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	// ErrRetryInvalid indicates a malformed notification retry request.
	ErrRetryInvalid = errors.New("invalid notification retry request")
	// ErrRetryConflict indicates an occurrence cannot safely be retried.
	ErrRetryConflict = errors.New("notification is not eligible for retry")
)

// RetryStore persists explicit retries and verifies routing identity atomically.
type RetryStore interface {
	// RetryNotification requeues an exhausted delivery only for its original destination identity.
	RetryNotification(context.Context, int64, string, map[string]string, time.Time) error
}

// RetryService validates operator requests and owns the configured destination identities.
type RetryService struct {
	// store owns the durable notification queue and retry journal.
	store RetryStore
	// identities contains only currently configured destinations.
	identities map[string]string
}

// NewRetryService snapshots the current destination identities for retry admission.
func NewRetryService(store RetryStore, targets map[string]Target) *RetryService {
	identities := make(map[string]string, len(targets))
	for name, target := range targets {
		identities[name] = target.Identity
	}
	return &RetryService{store: store, identities: identities}
}

// Retry gives one retained exhausted occurrence a fresh attempt budget.
func (s *RetryService) Retry(ctx context.Context, id int64, actor string, now time.Time) error {
	actor = strings.TrimSpace(actor)
	if id < 1 || len(actor) == 0 || len(actor) > 512 || strings.ContainsAny(actor, "\x00\r\n\t") {
		return ErrRetryInvalid
	}
	return s.store.RetryNotification(ctx, id, actor, s.identities, now)
}
