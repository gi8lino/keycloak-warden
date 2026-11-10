// Package maintenance schedules SQLite observation cleanup and query-planner optimization.
package maintenance

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	// DefaultPruneInterval preserves the existing hourly observation cleanup.
	DefaultPruneInterval = time.Hour
	// DefaultOptimizeInterval runs periodic SQLite planner optimization daily.
	DefaultOptimizeInterval = 24 * time.Hour
	// MinInterval is the shortest supported operational maintenance interval.
	MinInterval = 5 * time.Minute
	// MaxInterval bounds operational intervals against accidental overflow.
	MaxInterval = 365 * 24 * time.Hour
	// retryInterval avoids rapid retries when SQLite maintenance encounters an error.
	retryInterval = 5 * time.Second
)

// Schedule configures the independent database maintenance intervals.
type Schedule struct {
	// PruneInterval controls how often old login observations are deleted.
	PruneInterval time.Duration
	// OptimizeInterval controls how often SQLite query-planner statistics are refreshed.
	OptimizeInterval time.Duration
}

// Validate rejects maintenance intervals outside the supported range.
func (s Schedule) Validate() error {
	if s.PruneInterval < MinInterval || s.PruneInterval > MaxInterval {
		return fmt.Errorf("prune-interval must be between %d and %d", MinInterval, MaxInterval)
	}

	if s.OptimizeInterval < MinInterval || s.OptimizeInterval > MaxInterval {
		return fmt.Errorf("optimize-interval must be between %d and %d", MinInterval, MaxInterval)
	}

	return nil
}

// Store provides the independent SQLite maintenance operations.
type Store interface {
	// Prune deletes old observations, preserving current detection retention rules.
	Prune(context.Context, time.Time) error
	// Optimize refreshes SQLite's query-planner statistics.
	Optimize(context.Context) error
}

// Runner owns the maintenance worker until it is cancelled and joined.
type Runner struct {
	// cancel requests termination of ongoing or upcoming maintenance.
	cancel context.CancelFunc
	// done closes when maintenance releases the database.
	done chan struct{}
}

// Start schedules immediate pruning and recurring SQLite optimization.
// The initial SQLite optimization is performed separately when the store opens.
// The schedule must be validated before calling Start.
func Start(parent context.Context, store Store, schedule Schedule, logger *slog.Logger) *Runner {
	ctx, cancel := context.WithCancel(parent)
	runner := &Runner{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(runner.done)
		run(ctx, store, schedule, logger)
	}()
	return runner
}

// Close cancels maintenance and waits for database operations to finish.
// It is safe to call Close multiple times.
func (r *Runner) Close() {
	r.cancel()
	<-r.done
}

// run invokes due tasks independently and retries failures without stopping the server.
func run(ctx context.Context, store Store, schedule Schedule, logger *slog.Logger) {
	nextPrune := time.Time{}
	nextOptimize := time.Now().Add(schedule.OptimizeInterval)

	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextPrune) {
			if err := store.Prune(ctx, now); err != nil {
				if ctx.Err() == nil {
					logger.Warn(
						"observation cleanup failed",
						"event", "observation_cleanup_failed",
						"error", err,
					)
				}
				nextPrune = time.Now().Add(retryInterval)
			} else {
				nextPrune = time.Now().Add(schedule.PruneInterval)
			}
		}

		now = time.Now()
		if !now.Before(nextOptimize) && ctx.Err() == nil {
			if err := store.Optimize(ctx); err != nil {
				if ctx.Err() == nil {
					logger.Warn(
						"sqlite optimization failed",
						"event", "sqlite_optimize_failed",
						"error", err,
					)
				}
				nextOptimize = time.Now().Add(retryInterval)
			} else {
				nextOptimize = time.Now().Add(schedule.OptimizeInterval)
			}
		}

		deadline := nextPrune
		if nextOptimize.Before(deadline) {
			deadline = nextOptimize
		}

		waitUntil(ctx, deadline)
	}
}

// waitUntil sleeps until the next maintenance deadline or cancellation.
func waitUntil(ctx context.Context, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
