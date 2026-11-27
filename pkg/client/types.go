package client

import (
	"fmt"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// TaskStatus describes the outcome of one scheduled or manual maintenance task.
type TaskStatus struct {
	// Running reports whether the task is currently executing.
	Running bool `json:"running" yaml:"running"`
	// LastAttemptAt is the most recent attempt start time.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
	// LastSuccessAt is the most recent successful finish time.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty" yaml:"lastSuccessAt,omitempty"`
	// LastError describes the last failed attempt, if any.
	LastError string `json:"lastError,omitempty" yaml:"lastError,omitempty"`
}

// Maintenance is the housekeeping status returned by the application API.
type Maintenance struct {
	// State is the worker lifecycle reported by the scheduler.
	State model.WorkerState `json:"state" yaml:"state"`
	// StartedAt records when the maintenance worker started.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
	// Prune reports observation cleanup.
	Prune TaskStatus `json:"prune" yaml:"prune"`
	// Optimize reports SQLite planner optimization.
	Optimize TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval describes the configured cleanup frequency.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval describes the configured optimization frequency.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
}

// Error identifies a non-2xx administrative API response.
type Error struct {
	// Code is the upstream HTTP status code.
	Code int
	// Message is an optional bounded server-supplied explanation.
	Message string
}

// Error describes an unsuccessful request without exposing the bearer token.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("application HTTP %d", e.Code)
	}
	return fmt.Sprintf("application HTTP %d: %s", e.Code, e.Message)
}
