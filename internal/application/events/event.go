// Package events defines the normalized inputs accepted by detection.
package events

import "net/netip"

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
