package model

import "time"

// Incident records a named detection rule reaching its threshold.
type Incident struct {
	// ID identifies the persisted incident.
	ID int64 `json:"id"`
	// Rule identifies the matching detection policy.
	Rule string `json:"rule"`
	// GroupBy identifies the aggregation field.
	GroupBy string `json:"groupBy"`
	// GroupKey identifies the counted IP, user or realm.
	GroupKey string `json:"groupKey"`
	// IdentityRealm scopes a user aggregation key.
	IdentityRealm string `json:"identityRealm,omitempty"`
	// Distinct identifies the optional distinct field.
	Distinct string `json:"distinct,omitempty"`
	// Window is the original rule's counting duration.
	Window string `json:"window"`
	// Source identifies the event producer.
	Source string `json:"source"`
	// EventID identifies the triggering event.
	EventID string `json:"eventId"`
	// EventKind identifies the event category.
	EventKind string `json:"eventKind"`
	// EventType identifies the native user event type.
	EventType string `json:"eventType,omitempty"`
	// RealmID identifies the affected realm.
	RealmID string `json:"realmId"`
	// ActorRealmID identifies the administrator's authentication realm.
	ActorRealmID string `json:"actorRealmId,omitempty"`
	// UserID identifies the user or administrator.
	UserID string `json:"userId,omitempty"`
	// ClientID identifies the associated client.
	ClientID string `json:"clientId,omitempty"`
	// IP identifies the reported address when available.
	IP string `json:"ipAddress,omitempty"`
	// Error contains the native error code.
	Error string `json:"error,omitempty"`
	// OperationType identifies the administrative operation.
	OperationType string `json:"operationType,omitempty"`
	// ResourceType identifies the administrative resource type.
	ResourceType string `json:"resourceType,omitempty"`
	// ResourcePath identifies the affected resource.
	ResourcePath string `json:"resourcePath,omitempty"`
	// EventAt is the producer timestamp.
	EventAt time.Time `json:"eventAt"`
	// At is the processing time of the threshold hit.
	At time.Time `json:"at"`
	// Count is the number of matching observations or distinct keys.
	Count int `json:"count"`
	// Threshold is the configured minimum count.
	Threshold int `json:"threshold"`
	// BanUntil is the requested automatic ban expiry when applicable.
	BanUntil *time.Time `json:"banUntil,omitempty"`
	// EffectiveBanUntil is the longest requested automatic ban expiry across qualifying rules.
	EffectiveBanUntil *time.Time `json:"effectiveBanUntil,omitempty"`
	// DecisionID identifies the revised decision when enforcement changed.
	DecisionID string `json:"decisionId,omitempty"`
	// DecisionRevision identifies the resulting revision when enforcement changed.
	DecisionRevision int64 `json:"decisionRevision,omitempty"`
	// ObserveOnly indicates that enforcement was disabled for this occurrence.
	ObserveOnly bool `json:"observeOnly"`
}

// IncidentPage contains a bounded newest-first page of incidents.
type IncidentPage struct {
	// Items contains newest incidents first.
	Items []Incident `json:"items"`
	// NextBeforeID is the exclusive cursor for the next page, when available.
	NextBeforeID int64 `json:"nextBeforeId,omitempty"`
}
