// Package workerstate defines the lifecycle states shared by Warden workers and its public client.
package workerstate

// State identifies the current lifecycle of a background worker.
type State string

const (
	// StateIdle means the worker is running without actively processing work.
	StateIdle State = "idle"
	// StateProcessing means the worker is currently handling work.
	StateProcessing State = "processing"
	// StateStopped means the worker goroutine has exited.
	StateStopped State = "stopped"
)

// Valid reports whether the state is a supported worker lifecycle state.
func (s State) Valid() bool {
	return s == StateIdle || s == StateProcessing || s == StateStopped
}
