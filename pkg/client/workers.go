package client

import (
	"context"
	"net/http"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/workerstate"
)

// WorkerRuntime describes one worker's current process lifecycle.
type WorkerRuntime struct {
	// State is idle, processing, or stopped.
	State workerstate.State `json:"state" yaml:"state"`
	// StartedAt records the current process worker start.
	StartedAt time.Time `json:"startedAt" yaml:"startedAt"`
}

// ActionWorker extends worker runtime with durable queue statistics.
type ActionWorker struct {
	// WorkerRuntime supplies the common worker lifecycle.
	WorkerRuntime `yaml:",inline"`
	// PendingDeliveries counts current unattempted delivery revisions.
	PendingDeliveries int `json:"pendingDeliveries" yaml:"pendingDeliveries"`
	// RetryingDeliveries counts current revisions awaiting a retry.
	RetryingDeliveries int `json:"retryingDeliveries" yaml:"retryingDeliveries"`
	// ExhaustedDeliveries counts current revisions whose attempts are exhausted.
	ExhaustedDeliveries int `json:"exhaustedDeliveries" yaml:"exhaustedDeliveries"`
	// ActiveBans counts addresses with unexpired ban sources.
	ActiveBans int `json:"activeBans" yaml:"activeBans"`
	// NextDeadline identifies the earliest pending retry or source expiry.
	NextDeadline *time.Time `json:"nextDeadline,omitempty" yaml:"nextDeadline,omitempty"`
	// LastAttemptAt is the latest completed delivery attempt, including earlier runs.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
}

// MaintenanceWorker describes the scheduled maintenance lifecycle and task outcomes.
type MaintenanceWorker struct {
	// WorkerRuntime supplies the common worker lifecycle.
	WorkerRuntime `yaml:",inline"`
	// Prune contains the most recent observation cleanup outcome.
	Prune TaskStatus `json:"prune" yaml:"prune"`
	// Optimize contains the most recent SQLite optimization outcome.
	Optimize TaskStatus `json:"optimize" yaml:"optimize"`
	// PruneInterval configures the observation cleanup frequency.
	PruneInterval string `json:"pruneInterval" yaml:"pruneInterval"`
	// OptimizeInterval configures the SQLite optimization frequency.
	OptimizeInterval string `json:"optimizeInterval" yaml:"optimizeInterval"`
}

// Workers contains Warden's two observable background workers.
type Workers struct {
	// Actions owns expiry and destination delivery.
	Actions ActionWorker `json:"actions" yaml:"actions"`
	// Maintenance owns database housekeeping.
	Maintenance MaintenanceWorker `json:"maintenance" yaml:"maintenance"`
}

// WorkerStatus reads the read-only worker report from the authenticated application API.
func (c *Client) WorkerStatus(ctx context.Context) (Workers, error) {
	var result Workers
	if err := c.do(ctx, http.MethodGet, "/workers", nil, &result); err != nil {
		return Workers{}, err
	}
	return result, nil
}
