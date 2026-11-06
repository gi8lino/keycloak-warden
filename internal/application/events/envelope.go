package events

import "time"

// Envelope represents the public, versioned Snitch event contract.
// Transport adapters may decode it, while the application validates its meaning.
type Envelope struct {
	// Version selects the Snitch wire schema.
	Version int `json:"schemaVersion"`
	// ID identifies the event or decision in this response.
	ID string `json:"id"`
	// Source identifies the event producer.
	Source string `json:"source"`
	// Kind preserves the native Keycloak event type.
	Kind string `json:"type"`
	// Timestamp is the event time supplied by the producer.
	Timestamp time.Time `json:"timestamp"`
	// IP is the reported client address, which may be absent in an event.
	IP string `json:"ipAddress"`
}
