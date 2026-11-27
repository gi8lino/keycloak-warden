package model

import "time"

// NotificationDelivery describes one retained incident occurrence delivery.
type NotificationDelivery struct {
	// ID identifies the delivery independently of its incident.
	ID int64 `json:"id" yaml:"id"`
	// IncidentID identifies the original incident, which may have been pruned.
	IncidentID int64 `json:"incidentId" yaml:"incidentId"`
	// Destination is the configured webhook name.
	Destination string `json:"destination" yaml:"destination"`
	// Status is pending, retrying, delivered or exhausted.
	Status DeliveryStatus `json:"status" yaml:"status"`
	// Attempts counts all completed sends across retry cycles.
	Attempts int `json:"attempts" yaml:"attempts"`
	// NextAt is the scheduled retry or initial send time when pending.
	NextAt *time.Time `json:"nextAt,omitempty" yaml:"nextAt,omitempty"`
	// CompletedAt records the terminal completion time.
	CompletedAt *time.Time `json:"completedAt,omitempty" yaml:"completedAt,omitempty"`
	// LastError reports the latest recorded failed send, when available.
	LastError string `json:"lastError,omitempty" yaml:"lastError,omitempty"`
	// LastAttemptAt records the latest recorded send completion.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty" yaml:"lastAttemptAt,omitempty"`
}

// NotificationPage is a cursor-paginated list of incident deliveries.
type NotificationPage struct {
	// Items contains newest deliveries first.
	Items []NotificationDelivery `json:"items" yaml:"items"`
	// NextBeforeID is the exclusive cursor for the next page.
	NextBeforeID int64 `json:"nextBeforeId,omitempty" yaml:"nextBeforeId,omitempty"`
}

// NotificationAttempt records one completed outbound send.
type NotificationAttempt struct {
	// Number is the lifetime attempt number.
	Number int `json:"number" yaml:"number"`
	// CompletedAt records when the send completed.
	CompletedAt time.Time `json:"completedAt" yaml:"completedAt"`
	// Error describes a failed send; empty indicates acknowledgement.
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}

// NotificationAttemptPage contains a bounded page of recorded sends.
type NotificationAttemptPage struct {
	// Items contains attempts newest first.
	Items []NotificationAttempt `json:"items" yaml:"items"`
	// NextBeforeNumber is the exclusive cursor for older attempts.
	NextBeforeNumber int64 `json:"nextBeforeNumber,omitempty" yaml:"nextBeforeNumber,omitempty"`
}

// NotificationRetryRequest identifies the operator requesting a fresh attempt budget.
type NotificationRetryRequest struct {
	// Actor is asserted by the authenticated administrative caller.
	Actor string `json:"actor" yaml:"actor"`
}
