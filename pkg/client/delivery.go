package client

import (
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
)

// Delivery describes one destination's progress applying a decision revision.
type Delivery struct {
	// Destination names the configured provider.
	Destination string `json:"destination" yaml:"destination"`
	// Revision identifies the desired decision version.
	Revision int64 `json:"revision" yaml:"revision"`
	// DesiredState is the requested state when known.
	DesiredState decisionstate.State `json:"desiredState,omitempty" yaml:"desiredState,omitempty"`
	// Status is pending, retrying, delivered, exhausted, or superseded.
	Status deliverystate.Status `json:"status" yaml:"status"`
	// AcknowledgedAt records successful completion.
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty" yaml:"acknowledgedAt,omitempty"`
	// NextAttemptAt is the current retry deadline.
	NextAttemptAt *time.Time `json:"nextAttemptAt,omitempty" yaml:"nextAttemptAt,omitempty"`
	// SupersededByRevision identifies the revision that replaced unfinished work.
	SupersededByRevision int64 `json:"supersededByRevision,omitempty" yaml:"supersededByRevision,omitempty"`
	// AttemptsTruncated reports that older completed attempts were omitted from this page.
	AttemptsTruncated bool `json:"attemptsTruncated,omitempty" yaml:"attemptsTruncated,omitempty"`
	// Attempts lists the most recent completed provider calls in execution order.
	Attempts []DeliveryAttempt `json:"attempts,omitempty" yaml:"attempts,omitempty"`
}

// DeliveryAttempt records the result of one completed provider call.
type DeliveryAttempt struct {
	// Number counts recorded attempts within this delivery, starting at one.
	Number int64 `json:"number" yaml:"number"`
	// At is the UTC completion time.
	At time.Time `json:"at" yaml:"at"`
	// Outcome is either succeeded or failed.
	Outcome deliverystate.Outcome `json:"outcome" yaml:"outcome"`
	// Error contains the provider diagnostic for a failed attempt.
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}
