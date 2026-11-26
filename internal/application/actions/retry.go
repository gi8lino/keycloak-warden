package actions

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	// ErrRetryInvalid identifies malformed retry requests.
	ErrRetryInvalid = errors.New("invalid delivery retry request")
	// ErrRetryConflict identifies a delivery that cannot be retried in its current state.
	ErrRetryConflict = errors.New("delivery is not eligible for retry")
)

// RetryRequest identifies exactly one exhausted current-revision delivery.
type RetryRequest struct {
	// DecisionID identifies the stable decision.
	DecisionID string `json:"decisionId"`
	// Revision prevents stale operator actions from retrying newer decisions.
	Revision int64 `json:"revision"`
	// Destination identifies the configured target.
	Destination string `json:"destination"`
	// Actor is the identity asserted by the authenticated administrative caller.
	Actor string `json:"actor"`
}

// RetryStore atomically requeues one exhausted delivery and records the operator request.
type RetryStore interface {
	// RetryDelivery atomically checks eligibility, records the request and requeues the delivery.
	RetryDelivery(context.Context, RetryRequest, time.Time) error
}

// RetryService validates retry admission independently of transport and storage.
type RetryService struct {
	// store persists the retry and audit entry.
	store RetryStore
	// targets contains the enabled destination names.
	targets map[string]struct{}
}

// NewRetryService constructs an immutable retry admission service.
func NewRetryService(store RetryStore, names []string) (*RetryService, error) {
	if store == nil {
		return nil, errors.New("retry store is required")
	}

	targets := make(map[string]struct{}, len(names))
	for _, name := range names {
		targets[name] = struct{}{}
	}

	return &RetryService{
		store:   store,
		targets: targets,
	}, nil
}

// Retry schedules an exhausted current revision with a fresh attempt budget.
func (s *RetryService) Retry(ctx context.Context, request RetryRequest, now time.Time) error {
	request.Actor = strings.TrimSpace(request.Actor)

	if !validDecisionReference(request.DecisionID, request.Revision) {
		return ErrRetryInvalid
	}

	if !validActor(request.Actor) {
		return ErrRetryInvalid
	}

	if _, ok := s.targets[request.Destination]; !ok {
		return ErrRetryConflict
	}

	return s.store.RetryDelivery(ctx, request, now)
}

// validDecisionReference reports whether the decision ID and revision are valid.
func validDecisionReference(id string, revision int64) bool {
	return strings.TrimSpace(id) != "" &&
		len(id) <= 128 &&
		revision > 0
}

// validActor reports whether the actor is nonempty, bounded and free of forbidden characters.
func validActor(actor string) bool {
	return len(actor) > 0 &&
		len(actor) <= 512 &&
		!strings.ContainsAny(actor, "\x00\r\n\t")
}
