// Package actions dispatches durable desired state to named destinations.
package actions

import (
	"context"
	"log/slog"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

const (
	// drainBudget limits when a cycle may start another job; in-flight deliveries may finish later.
	drainBudget = time.Second
	// storageRetry defines the delay before retrying a failed storage operation.
	storageRetry = 5 * time.Second
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
	// Maintain expires decision sources and returns decisions released by a committed expiry.
	Maintain(context.Context, time.Time) ([]decisions.Decision, error)
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
	// err is written before done closes and read only after completion.
	err error
}

// Start launches the action worker and returns a runner that must be closed before its queue.
func Start(
	parent context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
) *Runner {
	ctx, cancel := context.WithCancel(parent)
	runner := &Runner{
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(runner.done)
		defer cancel()
		runner.err = run(ctx, q, destinations, logger)
	}()

	return runner
}

// Done closes when the worker has stopped and its terminal error is available.
func (r *Runner) Done() <-chan struct{} {
	return r.done
}

// Wait blocks until the worker stops and returns its terminal error.
func (r *Runner) Wait() error {
	<-r.done
	return r.err
}

// Close cancels the action worker and waits for completion; repeated calls are safe.
func (r *Runner) Close() error {
	r.cancel()
	return r.Wait()
}

// run processes durable work and waits for changes or scheduled deadlines.
func run(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
) error {
	for ctx.Err() == nil {
		deadline, err := processReady(ctx, q, destinations, logger)
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			logger.Warn("delivery worker failed",
				"event", "delivery_worker_failed",
				"error", err,
			)

			// Avoid a hot retry loop during storage outages.
			waitUntil(ctx, nil, time.Now().Add(storageRetry))
			continue
		}

		waitUntil(ctx, q.Changes(), deadline)
	}

	return nil
}

// processReady expires decision sources, delivers ready jobs, and finds the next deadline.
func processReady(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
) (nextDeadline time.Time, err error) {
	expired, err := q.Maintain(ctx, time.Now())
	if err != nil {
		return time.Time{}, err
	}
	for _, decision := range expired {
		logger.Info("ban expired",
			"event", "ban_expired",
			"decision_id", decision.ID,
			"revision", decision.Revision,
			"ip", decision.IP,
			"state", decision.State,
		)
	}

	if err := drainReady(ctx, q, destinations, logger, time.Now().Add(drainBudget)); err != nil {
		return time.Time{}, err
	}

	return q.NextDeadline(ctx)
}

// drainReady starts jobs within a soft time budget; it does not interrupt in-flight delivery.
func drainReady(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
	deadline time.Time,
) error {
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			// Stop processing if the context was cancelled or its deadline expired.
			return err
		}

		job, err := q.Next(ctx, time.Now())
		if err != nil {
			return err
		}
		if job == nil {
			return nil
		}

		if err := dispatch(ctx, q, destinations, logger, *job); err != nil {
			return err
		}
	}

	return ctx.Err()
}

// waitUntil sleeps until the deadline, a queued notification, or shutdown.
func waitUntil(ctx context.Context, changes <-chan struct{}, deadline time.Time) {
	if deadline.IsZero() {
		// No scheduled jobs: wait for an explicit change or shutdown.
		select {
		case <-ctx.Done():
		case <-changes:
		}
		return
	}

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-changes:
	case <-timer.C:
	}
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
		"state", job.Decision.State,
	)

	return q.Finish(ctx, job, true, time.Now())
}
