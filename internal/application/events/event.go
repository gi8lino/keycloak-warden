// Package events defines the Snitch event contract and normalized events used by detection.
package events

import "net/netip"

const (
	// SourceKeycloak identifies events emitted by the Keycloak Snitch listener.
	SourceKeycloak = "keycloak"
	// KindLoginError identifies failed Keycloak login attempts.
	KindLoginError = "LOGIN_ERROR"
)

// Event contains only the fields used for deduplication and detection.
type Event struct {
	// ID identifies an occurrence within the source.
	ID string
	// Source identifies the producer namespace.
	Source string
	// Kind identifies the original producer event type.
	Kind string
	// IP is the client address supplied by the authenticated source.
	IP netip.Addr
}
