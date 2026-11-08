// Package actions dispatches durable desired state to named destinations.
package actions

import (
	"context"
	"log/slog"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Job associates a decision revision with one configured destination.
type Job struct {
	// Decision is the state to reconcile.
	Decision decisions.Decision
	// Destination selects a configured provider instance.
	Destination string
}

// Provider reconciles the desired state and tolerates repeated delivery.
type Provider interface {
	// Apply reconciles one revision or returns a retryable error.
	Apply(context.Context, decisions.Decision) error
}

// Queue persists desired changes independently of external delivery.
type Queue interface {
	// Changes signals committed changes to delivery work or source expiries.
	Changes() <-chan struct{}
	// NextDeadline returns the earliest pending work time or zero when idle.
	NextDeadline(context.Context) (time.Time, error)
	// Prune removes observations beyond the retention window.
	Prune(context.Context, time.Time) error
	// Maintain expires decision sources.
	Maintain(context.Context, time.Time) error
	// Next returns the oldest ready destination job, or nil when idle.
	Next(context.Context, time.Time) (*Job, error)
	// Finish acknowledges the revision or schedules a retry.
	Finish(context.Context, Job, bool, time.Time) error
}

// Runner owns the background action worker and its cancellation lifecycle.
type Runner struct {
	// cancel stops the background worker through its context.
	cancel context.CancelFunc
	// done closes when the background worker has released its queue.
	done chan struct{}
}

// Start launches the action worker and returns a runner that must be closed before its queue.
func Start(parent context.Context, q Queue, destinations map[string]Provider, logger *slog.Logger) *Runner {
	ctx, cancel := context.WithCancel(parent)
	runner := &Runner{
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(runner.done)
		run(ctx, q, destinations, logger)
	}()

	return runner
}

// Close cancels the action worker and waits for it to stop using the queue.
// It is safe to call Close more than once.
func (r *Runner) Close() {
	r.cancel()
	<-r.done
}

const (
	pruneInterval = time.Hour
	drainBudget   = time.Second
	storageRetry  = 5 * time.Second
)

// run checks durable work at startup, then waits for commits or scheduled work.
func run(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
) {
	var nextPrune time.Time
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextPrune) {
			if err := q.Prune(ctx, now); err != nil {
				if ctx.Err() == nil {
					logger.Error(
						"observation cleanup failed",
						"event", "observation_cleanup_failed",
						"error", err,
					)
				}
				nextPrune = now.Add(storageRetry)
			} else {
				nextPrune = now.Add(pruneInterval)
			}
		}
		deadline, err := processReady(ctx, q, destinations, logger)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Error(
				"delivery worker failed",
				"event", "delivery_worker_failed",
				"error", err,
			)
			// Ignore notifications during a storage outage to avoid a hot retry loop.
			waitUntil(ctx, nil, time.Now().Add(storageRetry))
			continue
		}
		if deadline.IsZero() || nextPrune.Before(deadline) {
			deadline = nextPrune
		}
		waitUntil(ctx, q.Changes(), deadline)
	}
}

// processReady reconciles expired sources before delivery and computes the next wake time.
func processReady(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
) (time.Time, error) {
	if err := q.Maintain(ctx, time.Now()); err != nil {
		return time.Time{}, err
	}
	if err := drainReady(ctx, q, destinations, logger, time.Now().Add(drainBudget)); err != nil {
		return time.Time{}, err
	}
	return q.NextDeadline(ctx)
}

// waitUntil sleeps until the deadline, a queued notification, or shutdown.
func waitUntil(ctx context.Context, changes <-chan struct{}, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-changes:
	case <-timer.C:
	}
}

// drainReady dispatches pending jobs for one bounded maintenance interval.
func drainReady(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
	deadline time.Time,
) error {
	for ctx.Err() == nil && time.Now().Before(deadline) {
		job, err := q.Next(ctx, time.Now())
		if err != nil || job == nil {
			return err
		}
		if err := dispatch(ctx, q, destinations, logger, *job); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// dispatch records the outcome only for the revision that was attempted.
func dispatch(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
	job Job,
) error {
	log := logger.With(
		"decision_id", job.Decision.ID,
		"revision", job.Decision.Revision,
		"destination", job.Destination,
	)

	log.Debug(
		"delivering decision",
		"event", "delivery_starting",
		"ip", job.Decision.IP,
		"active", job.Decision.Active,
	)

	provider, ok := destinations[job.Destination]
	if !ok {
		log.Error(
			"destination missing from configuration",
			"event", "delivery_destination_missing",
		)
		return q.Finish(ctx, job, false, time.Now())
	}

	if err := provider.Apply(ctx, job.Decision); err != nil {
		log.Warn(
			"delivery failed",
			"event", "delivery_failed",
			"error", err,
		)
		return q.Finish(ctx, job, false, time.Now())
	}

	log.Info(
		"delivery completed",
		"event", "delivery_completed",
		"active", job.Decision.Active,
	)

	return q.Finish(ctx, job, true, time.Now())
}
