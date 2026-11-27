// Package maintenance schedules SQLite observation cleanup and query-planner optimization.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

const (
	// DefaultPruneInterval is the interval between observation cleanup runs.
	DefaultPruneInterval = time.Hour
	// DefaultOptimizeInterval runs periodic SQLite planner optimization daily.
	DefaultOptimizeInterval = 24 * time.Hour
	// MinInterval is the shortest supported operational maintenance interval.
	MinInterval = 5 * time.Minute
	// MaxInterval bounds operational intervals against accidental overflow.
	MaxInterval = 365 * 24 * time.Hour
	// MinObservationRetention preserves a full day of failed-login observations.
	MinObservationRetention = 24 * time.Hour
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

// Trigger identifies how a maintenance execution was initiated.
type Trigger string

const (
	// TriggerManual identifies an operator-requested execution.
	TriggerManual Trigger = "manual"
	// TriggerScheduled identifies an execution started by the scheduler.
	TriggerScheduled Trigger = "scheduled"
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
	if !validMaintenanceInterval(s.PruneInterval) {
		return fmt.Errorf("prune-interval must be between %s and %s", MinInterval, MaxInterval)
	}

	if !validMaintenanceInterval(s.OptimizeInterval) {
		return fmt.Errorf("optimize-interval must be between %s and %s", MinInterval, MaxInterval)
	}

	return nil
}

// validMaintenanceInterval checks the inclusive scheduling bounds for maintenance jobs.
func validMaintenanceInterval(interval time.Duration) bool {
	return interval >= MinInterval && interval <= MaxInterval
}

// Store provides the independent SQLite maintenance operations.
type Store interface {
	// Prune deletes observations at or before the application-supplied cutoff.
	Prune(context.Context, time.Time) error
	// Optimize refreshes SQLite's query-planner statistics.
	Optimize(context.Context) error
}

// TaskStatus describes the latest attempt for one maintenance operation.
type TaskStatus struct {
	// Running indicates that an attempt is currently in progress.
	Running bool `json:"running" yaml:"running"`
	// LastAttemptAt records when the most recent attempt began.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
	// LastSuccessAt records when the most recent successful attempt completed.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty" yaml:"lastSuccessAt,omitempty"`
	// LastError reports the last failed attempt, cleared after success.
	LastError string `json:"lastError,omitempty" yaml:"lastError,omitempty"`
}

// Status is a safe snapshot of the maintenance worker and its scheduled tasks.
type Status struct {
	// State is idle, processing, or stopped.
	State model.WorkerState `json:"state" yaml:"state"`
	// StartedAt records when the maintenance worker was started.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
	// Prune reports the last observation cleanup attempt.
	Prune TaskStatus `json:"prune" yaml:"prune"`
	// Optimize reports the last SQLite optimization attempt.
	Optimize TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval describes the configured recurring cleanup interval.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval describes the configured recurring optimization interval.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
}

// Runner owns the maintenance worker and serializes scheduled and manual operations.
type Runner struct {
	// cancel requests termination of ongoing or upcoming maintenance.
	cancel context.CancelFunc
	// done closes when maintenance releases the database.
	done chan struct{}
	// store executes bounded SQLite maintenance operations.
	store Store
	// startedAt records the worker launch timestamp.
	startedAt time.Time
	// schedule configures normal recurrence.
	schedule Schedule
	// retention determines how long detection observations remain available.
	retention time.Duration
	// logger records maintenance outcomes independently of HTTP access logging.
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
func Start(
	parent context.Context,
	store Store,
	schedule Schedule,
	retention time.Duration,
	logger *slog.Logger,
) *Runner {
	ctx, cancel := context.WithCancel(parent)

	runner := &Runner{
		cancel:    cancel,
		done:      make(chan struct{}),
		startedAt: time.Now().UTC(),
		store:     store,
		schedule:  schedule,
		retention: retention,
		logger:    logger,
	}

	go runner.runUntilDone(ctx)

	return runner
}

// runUntilDone closes the worker completion channel only after maintenance has stopped.
func (r *Runner) runUntilDone(ctx context.Context) {
	defer close(r.done)
	r.run(ctx)
}

// Close cancels maintenance and waits for completion; repeated calls are safe.
func (r *Runner) Close() {
	r.cancel()
	<-r.done
}

// Snapshot returns the worker lifecycle and task history without querying SQLite.
func (r *Runner) Snapshot() Status {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()

	state := model.WorkerIdle
	select {
	case <-r.done:
		state = model.WorkerStopped
	default:
		if r.pruneStatus.Running || r.optimizeStatus.Running {
			state = model.WorkerProcessing
		}
	}

	return Status{
		State:            state,
		StartedAt:        r.startedAt,
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

	return r.execute(ctx, operation, TriggerManual)
}

// execute records the outcome of an operation while executeMu is held.
func (r *Runner) execute(ctx context.Context, operation Operation, trigger Trigger) error {
	started := time.Now()
	now := started.UTC()
	r.statusMu.Lock()
	status := r.statusFor(operation)
	status.Running = true
	status.LastAttemptAt = &now
	r.statusMu.Unlock()

	var err error
	switch operation {
	case OperationPrune:
		err = r.store.Prune(ctx, now.Add(-r.retention))
	case OperationOptimize:
		err = r.store.Optimize(ctx)
	default:
		err = ErrInvalidOperation
	}

	r.statusMu.Lock()
	status.Running = false
	if err == nil {
		status.LastSuccessAt = new(time.Now().UTC())
		status.LastError = ""
	} else {
		status.LastError = err.Error()
	}
	r.statusMu.Unlock()

	r.logOutcome(operation, trigger, started, err)
	return err
}

// logOutcome records actual execution results without attributing callers from untrusted headers.
func (r *Runner) logOutcome(operation Operation, trigger Trigger, started time.Time, err error) {
	logger := r.logger.With(
		"operation", operation,
		"trigger", trigger,
		"duration_ms", float64(time.Since(started))/float64(time.Millisecond),
	)

	if err != nil {
		logger.Warn("database maintenance failed",
			"event", "database_maintenance_failed",
			"outcome", "failed",
			"error", err,
		)
		return
	}
	logger.Info("database maintenance completed",
		"event", "database_maintenance_completed",
		"outcome", "completed",
	)
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
			err := r.execute(ctx, OperationPrune, TriggerScheduled)
			r.executeMu.Unlock()

			interval := r.schedule.PruneInterval
			if err != nil {
				interval = retryInterval
			}
			nextPrune = time.Now().Add(interval)
		}

		now = time.Now()
		if !now.Before(nextOptimize) && ctx.Err() == nil {
			r.executeMu.Lock()
			err := r.execute(ctx, OperationOptimize, TriggerScheduled)
			r.executeMu.Unlock()

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
