// Package maintenance schedules SQLite observation cleanup and query-planner optimization.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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

var (
	// ErrBusy indicates another maintenance operation is in progress.
	ErrBusy = errors.New("database maintenance is already running")
	// ErrInvalidOperation identifies an unsupported manually requested operation.
	ErrInvalidOperation = errors.New("invalid database maintenance operation")
)

// Operation identifies a supported SQLite maintenance action.
type Operation string

const (
	// OperationPrune deletes expired failure observations.
	OperationPrune Operation = "prune"
	// OperationOptimize refreshes SQLite query-planner statistics.
	OperationOptimize Operation = "optimize"
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
		return fmt.Errorf("prune-interval must be between %s and %s", MinInterval, MaxInterval)
	}
	if s.OptimizeInterval < MinInterval || s.OptimizeInterval > MaxInterval {
		return fmt.Errorf("optimize-interval must be between %s and %s", MinInterval, MaxInterval)
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

// TaskStatus describes the latest attempt for one maintenance operation.
type TaskStatus struct {
	// Running indicates that an attempt is currently in progress.
	Running bool `json:"running"`
	// LastAttemptAt records when the most recent attempt began.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
	// LastSuccessAt records when the most recent successful attempt completed.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
	// LastError reports the last failed attempt, cleared after success.
	LastError string `json:"lastError,omitempty"`
}

// Status is a safe snapshot of the in-process maintenance scheduler.
type Status struct {
	// Prune reports the last observation cleanup attempt.
	Prune TaskStatus `json:"prune"`
	// Optimize reports the last SQLite optimization attempt.
	Optimize TaskStatus `json:"optimize"`
	// PruneInterval describes the configured recurring cleanup interval.
	PruneInterval string `json:"pruneInterval"`
	// OptimizeInterval describes the configured recurring optimization interval.
	OptimizeInterval string `json:"optimizeInterval"`
}

// Runner owns the maintenance worker and serializes scheduled and manual operations.
type Runner struct {
	// cancel requests termination of ongoing or upcoming maintenance.
	cancel context.CancelFunc
	// done closes when maintenance releases the database.
	done chan struct{}
	// store executes bounded SQLite maintenance operations.
	store Store
	// schedule configures normal recurrence.
	schedule Schedule
	// logger records background maintenance failures.
	logger *slog.Logger
	// executeMu prevents concurrent maintenance from overlapping.
	executeMu sync.Mutex
	// statusMu protects the most recent outcomes.
	statusMu sync.Mutex
	// pruneStatus is the observation cleanup status.
	pruneStatus TaskStatus
	// optimizeStatus is the planner optimization status.
	optimizeStatus TaskStatus
}

// Start schedules maintenance using a prevalidated schedule; SQLite is optimized separately on open.
func Start(parent context.Context, store Store, schedule Schedule, logger *slog.Logger) *Runner {
	ctx, cancel := context.WithCancel(parent)
	runner := &Runner{
		cancel:   cancel,
		done:     make(chan struct{}),
		store:    store,
		schedule: schedule,
		logger:   logger,
	}
	go func() {
		defer close(runner.done)
		runner.run(ctx)
	}()
	return runner
}

// Close cancels maintenance and waits for completion; repeated calls are safe.
func (r *Runner) Close() {
	r.cancel()
	<-r.done
}

// Snapshot returns the last attempt state without waiting on SQLite.
func (r *Runner) Snapshot() Status {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	return Status{
		Prune:            r.pruneStatus,
		Optimize:         r.optimizeStatus,
		PruneInterval:    r.schedule.PruneInterval.String(),
		OptimizeInterval: r.schedule.OptimizeInterval.String(),
	}
}

// Trigger runs one operator-requested maintenance operation and returns ErrBusy on overlap.
func (r *Runner) Trigger(ctx context.Context, operation Operation) error {
	if operation != OperationPrune && operation != OperationOptimize {
		return ErrInvalidOperation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !r.executeMu.TryLock() {
		return ErrBusy
	}
	defer r.executeMu.Unlock()
	return r.execute(ctx, operation)
}

// execute records the outcome of an operation while executeMu is held.
func (r *Runner) execute(ctx context.Context, operation Operation) error {
	now := time.Now().UTC()
	r.statusMu.Lock()
	status := r.statusFor(operation)
	status.Running = true
	status.LastAttemptAt = &now
	r.statusMu.Unlock()

	var err error
	switch operation {
	case OperationPrune:
		err = r.store.Prune(ctx, now)
	case OperationOptimize:
		err = r.store.Optimize(ctx)
	default:
		err = ErrInvalidOperation
	}

	r.statusMu.Lock()
	status.Running = false
	if err == nil {
		completed := time.Now().UTC()
		status.LastSuccessAt = &completed
		status.LastError = ""
	} else {
		status.LastError = err.Error()
	}
	r.statusMu.Unlock()
	return err
}

// statusFor returns the protected status value; statusMu must be held.
func (r *Runner) statusFor(operation Operation) *TaskStatus {
	if operation == OperationPrune {
		return &r.pruneStatus
	}
	return &r.optimizeStatus
}

// run invokes scheduled maintenance independently and retries failures without terminating Warden.
func (r *Runner) run(ctx context.Context) {
	nextPrune := time.Time{}
	nextOptimize := time.Now().Add(r.schedule.OptimizeInterval)
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextPrune) {
			r.executeMu.Lock()
			err := r.execute(ctx, OperationPrune)
			r.executeMu.Unlock()
			if err != nil && ctx.Err() == nil {
				r.logger.Warn(
					"observation cleanup failed",
					"event", "observation_cleanup_failed",
					"error", err,
				)
			}
			interval := r.schedule.PruneInterval
			if err != nil {
				interval = retryInterval
			}
			nextPrune = time.Now().Add(interval)
		}
		now = time.Now()
		if !now.Before(nextOptimize) && ctx.Err() == nil {
			r.executeMu.Lock()
			err := r.execute(ctx, OperationOptimize)
			r.executeMu.Unlock()
			if err != nil && ctx.Err() == nil {
				r.logger.Warn(
					"sqlite optimization failed",
					"event", "sqlite_optimize_failed",
					"error", err,
				)
			}
			interval := r.schedule.OptimizeInterval
			if err != nil {
				interval = retryInterval
			}
			nextOptimize = time.Now().Add(interval)
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
