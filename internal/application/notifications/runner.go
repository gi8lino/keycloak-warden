// Package notifications dispatches durable incident occurrences independently of enforcement.
package notifications

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

const (
	// storageRetry bounds the pause after a queue access error.
	storageRetry = 5 * time.Second
)

// Job is one persisted incident delivery to a named destination.
type Job struct {
	// ID identifies the durable queue row.
	ID int64
	// Incident is the immutable occurrence snapshot.
	Incident model.Incident
	// Destination identifies the configured sender.
	Destination string
	// Attempts counts previously completed sends.
	Attempts int
	// RetryBaseline is the completed attempt count at the last explicit retry.
	RetryBaseline int
	// Delay is the previous persisted retry pause.
	Delay time.Duration
}

// Provider sends a single incident occurrence.
type Provider interface {
	// Deliver acknowledges the occurrence or returns a retryable error.
	Deliver(context.Context, model.Incident) error
}

// Target binds a sender to its routing identity and attempt budget.
type Target struct {
	// Provider sends the occurrence.
	Provider Provider
	// Identity fingerprints the endpoint and routing variables.
	Identity string
	// MaxAttempts bounds total delivery attempts.
	MaxAttempts int
}

// Queue owns notification persistence independently of ban revisions.
type Queue interface {
	// NotificationChanges wakes the worker after committed notification admissions.
	NotificationChanges() <-chan struct{}
	// NextNotificationDeadline returns the earliest eligible job time or zero when idle.
	NextNotificationDeadline(context.Context) (time.Time, error)
	// NextNotification returns a ready job or nil when idle.
	NextNotification(context.Context, time.Time) (*Job, error)
	// FinishNotification records a completed attempt, retry or terminal outcome.
	FinishNotification(context.Context, Job, Completion) error
}

// Runner owns one independent notification worker.
type Runner struct {
	// cancel stops new attempts and cancels in-flight HTTP requests.
	cancel context.CancelFunc
	// done closes after the worker exits.
	done chan struct{}
	// startedAt records the worker launch time.
	startedAt time.Time
	// processing marks an active queue cycle.
	processing atomic.Bool
}

// Start launches the notification worker; close it before closing the store.
func Start(parent context.Context, queue Queue, targets map[string]Target, policy retry.RetryPolicy, logger *slog.Logger) *Runner {
	ctx, cancel := context.WithCancel(parent)
	runner := &Runner{
		cancel:    cancel,
		done:      make(chan struct{}),
		startedAt: time.Now().UTC(),
	}
	if logger == nil {
		logger = slog.Default()
	}
	go func() {
		defer close(runner.done)
		run(ctx, queue, targets, policy, logger, &runner.processing)
	}()
	return runner
}

// Done closes after the notification worker stops.
func (r *Runner) Done() <-chan struct{} { return r.done }

// Close cancels delivery and waits until the worker has stopped.
func (r *Runner) Close() {
	r.cancel()
	<-r.done
}

// run processes ready jobs and otherwise waits for new work or a persisted deadline.
func run(ctx context.Context, queue Queue, targets map[string]Target, policy retry.RetryPolicy, logger *slog.Logger, processing *atomic.Bool) {
	for ctx.Err() == nil {
		processing.Store(true)
		job, err := queue.NextNotification(ctx, time.Now())
		if err == nil && job != nil {
			err = deliver(ctx, queue, targets, policy, logger, *job)
			if err == nil {
				processing.Store(false)
				continue
			}
		}

		var deadline time.Time
		if err == nil {
			deadline, err = queue.NextNotificationDeadline(ctx)
		}
		processing.Store(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Error("notification queue unavailable", "event", "notification_queue_error", "error", err)
			waitUntil(ctx, nil, time.Now().Add(storageRetry))
			continue
		}

		waitUntil(ctx, queue.NotificationChanges(), deadline)
	}
}

// waitUntil waits for new work, a scheduled retry or cancellation.
func waitUntil(ctx context.Context, changes <-chan struct{}, deadline time.Time) {
	if deadline.IsZero() {
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

// deliver sends an occurrence outside the database transaction and records its outcome.
func deliver(ctx context.Context, queue Queue, targets map[string]Target, policy retry.RetryPolicy, logger *slog.Logger, job Job) error {
	target, ok := targets[job.Destination]
	if !ok {
		return errors.New("queued notification destination unavailable")
	}
	var sendErr error
	if job.Attempts-job.RetryBaseline < target.MaxAttempts {
		sendErr = target.Provider.Deliver(ctx, job.Incident)
	} else {
		sendErr = errors.New("notification attempt budget exhausted")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	completion := Complete(job, sendErr, target.MaxAttempts, time.Now(), policy.NextDelay(job.Delay))
	if err := queue.FinishNotification(ctx, job, completion); err != nil {
		return err
	}
	if sendErr != nil {
		logger.Warn("notification delivery failed",
			"event", "notification_failed",
			"incident_id", job.Incident.ID,
			"destination", job.Destination,
			"attempt", completion.Attempts,
			"exhausted", completion.State == Exhausted,
			"error", sendErr,
		)
	} else {
		logger.Info("notification delivered",
			"event", "notification_completed",
			"incident_id", job.Incident.ID,
			"destination", job.Destination,
		)
	}
	return nil
}
