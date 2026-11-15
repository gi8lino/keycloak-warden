// Package decisions defines the desired security state shared by storage and delivery.
package decisions

import (
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// Decision describes the latest desired state for one address.
type Decision struct {
	// ID is stable across revisions for this address in this database.
	ID string `json:"id" yaml:"id"`
	// Revision increases each time the desired state changes.
	Revision int64 `json:"revision" yaml:"revision"`
	// IP is the canonical address to block or release.
	IP string `json:"ipAddress" yaml:"ipAddress"`
	// State is the desired block or release operation.
	State decisionstate.State `json:"state" yaml:"state"`
	// ExpiresAt is the deadline for the desired block.
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
}
