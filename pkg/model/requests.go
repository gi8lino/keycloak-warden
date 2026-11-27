package model

import "time"

// CreateBanRequest is the JSON body for a manual ban.
type CreateBanRequest struct {
	// IP is the address requested by the operator.
	IP string `json:"ipAddress"`
	// Duration specifies how long the requested manual block should last.
	Duration string `json:"duration"`
	// Reason records the operator explanation for the requested block.
	Reason string `json:"reason"`
}

// RetryRequest identifies exactly one exhausted current-revision delivery.
type RetryRequest struct {
	// DecisionID identifies the stable decision.
	DecisionID string `json:"decisionId"`
	// Revision prevents stale operator actions from retrying newer decisions.
	Revision int64 `json:"revision"`
	// Destination identifies the configured target.
	Destination string `json:"destination"`
	// Actor is the identity asserted by the authenticated administrative caller.
	Actor string `json:"actor"`
}

// RetryResponse reports whether a delivery retry was queued.
type RetryResponse struct {
	// Queued indicates that the retry was accepted.
	Queued bool `json:"queued"`
}

// ManualBanRequest specifies a new or extended operator-requested block.
type ManualBanRequest struct {
	// IP is the reported client address, provided by the operator.
	IP string
	// Duration specifies how long the requested manual block should last.
	Duration time.Duration
	// Reason records the operator explanation for the requested block.
	Reason string
}
