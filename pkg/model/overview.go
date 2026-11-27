package model

import "time"

// Revision is one immutable snapshot of a changed desired decision.
type Revision struct {
	// DecisionID identifies the stable decision that owns this revision.
	DecisionID string `json:"decisionId"`
	// IPAddress is the canonical address that the decision concerns.
	IPAddress string `json:"ipAddress"`
	// Revision is the monotonically increasing decision version.
	Revision int64 `json:"revision"`
	// State is the desired blocking state recorded at this revision.
	State DecisionState `json:"state"`
	// Cause identifies the workflow that created this revision.
	Cause ChangeCause `json:"cause"`
	// ExpiresAt is the deadline recorded for this decision revision.
	ExpiresAt time.Time `json:"expiresAt"`
	// ChangedAt is when the transaction committed this revision.
	ChangedAt time.Time `json:"changedAt"`
	// Sources contains the reasons that were active at this revision.
	Sources []Source `json:"sources"`
}

// RevisionPage contains bounded, newest-first decision changes.
type RevisionPage struct {
	// Items contains the selected immutable decision revisions.
	Items []Revision `json:"items"`
	// Page identifies this one-based page.
	Page int `json:"page"`
	// NextPage is the next older page, or zero when the page is final.
	NextPage int `json:"nextPage,omitempty"`
	// ThroughSequence anchors future pages to the same journal membership.
	ThroughSequence int64 `json:"throughSequence,omitempty"`
}

// DeliveryOverview is the current revision's progress for one destination and decision.
type DeliveryOverview struct {
	// DecisionID identifies the decision associated with this destination.
	DecisionID string `json:"decisionId"`
	// IPAddress is the canonical decision address.
	IPAddress string `json:"ipAddress"`
	// Revision identifies the current desired decision version.
	Revision int64 `json:"revision"`
	// DesiredState is the latest state requested by Warden.
	DesiredState DecisionState `json:"desiredState"`
	// Destination is the configured target identifier.
	Destination string `json:"destination"`
	// Status is the current revision delivery lifecycle.
	Status DeliveryStatus `json:"status"`
	// AcknowledgedRevision is the last accepted version, or zero when absent.
	AcknowledgedRevision int64 `json:"acknowledgedRevision"`
	// AttemptCount is the number of completed current-revision attempts.
	AttemptCount int64 `json:"attemptCount"`
	// ChangedAt is the decision revision commit time when known.
	ChangedAt *time.Time `json:"changedAt,omitempty"`
	// LastAttemptAt is the latest completed provider call time.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
	// NextAttemptAt is the next scheduled retry when applicable.
	NextAttemptAt *time.Time `json:"nextAttemptAt,omitempty"`
	// LastError is a bounded diagnostic from the latest provider call.
	LastError string `json:"lastError,omitempty"`
}

// DeliveryOverviewPage contains bounded current-state reconciliation entries.
type DeliveryOverviewPage struct {
	// Items contains the selected current-revision destination entries.
	Items []DeliveryOverview `json:"items"`
	// Page identifies this one-based page.
	Page int `json:"page"`
	// NextPage is the next older page, or zero when the page is final.
	NextPage int `json:"nextPage,omitempty"`
}
