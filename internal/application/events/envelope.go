package events

import "time"

// Envelope represents the complete, versioned Snitch event contract.
type Envelope struct {
	// Version identifies the Snitch event schema.
	Version int `json:"schemaVersion"`
	// ID uniquely identifies the event.
	ID string `json:"id"`
	// Source identifies the event producer.
	Source string `json:"source"`
	// Kind is the original Keycloak event type.
	Kind string `json:"type"`
	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`
	// RealmID identifies the originating Keycloak realm.
	RealmID string `json:"realmId"`
	// ClientID identifies the Keycloak client.
	ClientID string `json:"clientId"`
	// UserID identifies the associated Keycloak user, when available.
	UserID string `json:"userId"`
	// IP is the reported client address.
	IP string `json:"ipAddress"`
	// Error describes the Keycloak authentication failure, when available.
	Error string `json:"error"`
}
