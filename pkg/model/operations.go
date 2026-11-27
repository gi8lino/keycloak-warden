package model

import "time"

// DestinationHealth aggregates current delivery states across all decisions for a destination.
type DestinationHealth struct {
	// Destination is the provider-qualified name.
	Destination string `json:"destination"`
	// Pending counts deliveries awaiting their first attempt or explicit retry.
	Pending int64 `json:"pending"`
	// Retrying counts failed deliveries scheduled to retry.
	Retrying int64 `json:"retrying"`
	// Exhausted counts failed deliveries without an automatic retry budget.
	Exhausted int64 `json:"exhausted"`
	// FailedUnbans counts retrying or exhausted releases.
	FailedUnbans int64 `json:"failedUnbans"`
	// ExhaustedUnbans counts releases requiring operator intervention.
	ExhaustedUnbans int64 `json:"exhaustedUnbans"`
	// Delivered counts acknowledged current revisions.
	Delivered int64 `json:"delivered"`
}

// TimelineEvent describes a persisted audit event.
type TimelineEvent struct {
	// At is the recorded event timestamp.
	At time.Time `json:"at"`
	// Kind distinguishes source, decision, attempt and retry records.
	Kind string `json:"kind"`
	// Action identifies the recorded transition or outcome.
	Action string `json:"action"`
	// SourceKind identifies the affected source for source mutations.
	SourceKind string `json:"sourceKind,omitempty"`
	// State identifies the desired state for a decision revision.
	State string `json:"state,omitempty"`
	// Revision is the decision revision when known.
	Revision int64 `json:"revision,omitempty"`
	// Destination identifies the delivery target when applicable.
	Destination string `json:"destination,omitempty"`
	// Detail contains a bounded source reason or delivery error.
	Detail string `json:"detail,omitempty"`
	// Actor is the caller-asserted identity for an explicit retry.
	Actor string `json:"actor,omitempty"`
	// ExpiresAt records a source or decision deadline, not an actual release time.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// Attempt is the historical attempt number when applicable.
	Attempt int64 `json:"attempt,omitempty"`
}

// TimelinePage returns a bounded newest-first view of recorded events.
type TimelinePage struct {
	// DecisionID identifies the selected decision.
	DecisionID string `json:"decisionId"`
	// IP identifies the selected decision's address.
	IP string `json:"ipAddress"`
	// Items contains the events on this page.
	Items []TimelineEvent `json:"items"`
	// Page identifies this page.
	Page int `json:"page"`
	// NextPage identifies the next older page if present.
	NextPage int `json:"nextPage,omitempty"`
}

// ObservationPage returns recent hypothetical automatic bans.
type ObservationPage struct {
	// Items contains recorded threshold hits.
	Items []Observation `json:"items"`
	// Page identifies this page.
	Page int `json:"page"`
	// NextPage identifies the next older page if present.
	NextPage int `json:"nextPage,omitempty"`
}

// Observation describes a threshold hit that would have requested an automatic ban.
type Observation struct {
	// Source identifies the event producer.
	Source string `json:"source"`
	// EventID identifies the triggering event.
	EventID string `json:"eventId"`
	// IP is the canonical address.
	IP string `json:"ipAddress"`
	// At is the observation time.
	At time.Time `json:"at"`
	// ExpiresAt is the hypothetical automatic source expiry.
	ExpiresAt time.Time `json:"expiresAt"`
	// Failures is the observed count.
	Failures int `json:"failures"`
	// Threshold is the configured trigger count.
	Threshold int `json:"threshold"`
}
