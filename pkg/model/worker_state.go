package model

// WorkerState identifies the current lifecycle of a background worker.
type WorkerState string

const (
	// WorkerIdle means the worker is running without actively processing work.
	WorkerIdle WorkerState = "idle"
	// WorkerProcessing means the worker is currently handling work.
	WorkerProcessing WorkerState = "processing"
	// WorkerStopped means the worker goroutine has exited.
	WorkerStopped WorkerState = "stopped"
)

// Valid reports whether the state is a supported worker lifecycle state.
func (s WorkerState) Valid() bool {
	return s == WorkerIdle || s == WorkerProcessing || s == WorkerStopped
}
