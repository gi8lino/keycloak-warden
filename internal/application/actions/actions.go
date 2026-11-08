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
	// Maintain expires decisions and prunes old observations.
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

const maintenanceInterval = time.Second

// run maintains decisions periodically and dispatches ready work until cancellation.
func run(ctx context.Context, q Queue, destinations map[string]Provider, logger *slog.Logger) {
	ticker := time.NewTicker(maintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			if err := q.Maintain(ctx, now); err != nil {
				if ctx.Err() == nil {
					logger.Error(
						"decision maintenance failed",
						"event", "decision_maintenance_failed",
						"error", err,
					)
				}
				continue
			}
			drainReady(ctx, q, destinations, logger, now.Add(maintenanceInterval))
		}
	}
}

// drainReady dispatches pending jobs for one bounded maintenance interval.
func drainReady(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
	deadline time.Time,
) {
	for ctx.Err() == nil && time.Now().Before(deadline) {
		job, err := q.Next(ctx, time.Now())
		if err != nil {
			if ctx.Err() == nil {
				logger.Error(
					"read delivery queue",
					"event", "delivery_queue_read_failed",
					"error", err,
				)
			}
			return
		}
		if job == nil || !dispatch(ctx, q, destinations, logger, *job) {
			return
		}
	}
}

// dispatch records the outcome only for the revision that was attempted.
func dispatch(
	ctx context.Context,
	q Queue,
	destinations map[string]Provider,
	logger *slog.Logger,
	job Job,
) bool {
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
		return finishJob(ctx, q, job, log, false)
	}

	if err := provider.Apply(ctx, job.Decision); err != nil {
		log.Warn("delivery failed", "event", "delivery_failed", "error", err)
		return finishJob(ctx, q, job, log, false)
	}

	log.Info(
		"delivery completed",
		"event", "delivery_completed",
		"active", job.Decision.Active,
	)

	return finishJob(ctx, q, job, log, true)
}

// finishJob persists the attempted revision outcome before the worker takes another job.
func finishJob(ctx context.Context, q Queue, job Job, log *slog.Logger, success bool) bool {
	if err := q.Finish(ctx, job, success, time.Now()); err != nil {
		log.Error(
			"persist delivery outcome",
			"event", "delivery_outcome_write_failed",
			"error", err,
		)
		return false
	}
	return true
}
