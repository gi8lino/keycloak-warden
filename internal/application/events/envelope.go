// Package events defines and validates the Snitch event contract.
package events

import (
	"net/netip"
	"time"
)

const (
	// SourceKeycloak identifies events emitted by the Keycloak Snitch listener.
	SourceKeycloak = "keycloak"
	// KindUser identifies user events.
	KindUser = "user"
	// KindAdmin identifies administrative events.
	KindAdmin = "admin"
	// TypeLoginError identifies failed Keycloak login attempts.
	TypeLoginError = "LOGIN_ERROR"
)

// SchemaVersion identifies the Snitch event schema.
const SchemaVersion = 2

// Envelope carries exactly one typed Snitch event.
type Envelope struct {
	// Version identifies the Snitch event schema.
	Version int `json:"schemaVersion"`
	// ID uniquely identifies the event within its source.
	ID string `json:"id"`
	// Source identifies the producer.
	Source string `json:"source"`
	// Kind identifies the event category.
	Kind string `json:"kind"`
	// Timestamp is the producer event time.
	Timestamp time.Time `json:"timestamp"`
	// User contains native user event data.
	User *UserEvent `json:"user,omitempty"`
	// Admin contains administrative event data.
	Admin *AdminEvent `json:"admin,omitempty"`
}

// UserEvent carries native Keycloak user event data.
type UserEvent struct {
	// Type identifies the native event type.
	Type string `json:"type"`
	// RealmID identifies the event realm.
	RealmID string `json:"realmId"`
	// ClientID identifies the client.
	ClientID string `json:"clientId"`
	// UserID identifies the user when known.
	UserID string `json:"userId"`
	// IP is the address reported by Keycloak.
	IP string `json:"ipAddress"`
	// Error contains the native error code.
	Error string `json:"error"`
}

// AdminEvent carries metadata about an administrative operation.
type AdminEvent struct {
	// RealmID identifies the affected realm.
	RealmID string `json:"realmId"`
	// OperationType identifies the native operation.
	OperationType string `json:"operationType"`
	// ResourceType identifies the affected resource category.
	ResourceType string `json:"resourceType"`
	// ResourcePath identifies the affected resource.
	ResourcePath string `json:"resourcePath"`
	// Actor identifies the acting administrator when available.
	Actor *Actor `json:"actor"`
	// Error contains the native error code.
	Error string `json:"error"`
}

// Actor identifies the administrator performing an operation.
type Actor struct {
	// RealmID identifies the administrator's authentication realm.
	RealmID string `json:"realmId"`
	// ClientID identifies the native administrative client.
	ClientID string `json:"clientId"`
	// UserID identifies the administrator.
	UserID string `json:"userId"`
	// IP is the address reported by Keycloak.
	IP string `json:"ipAddress"`
}

// validPayload checks that exactly one event matches the declared category.
func (e Envelope) validPayload() bool {
	switch e.Kind {
	case KindUser:
		return e.User != nil && e.Admin == nil
	case KindAdmin:
		return e.Admin != nil && e.User == nil
	default:
		return false
	}
}

// RealmID returns the affected realm for the selected category.
func (e Envelope) RealmID() string {
	switch e.Kind {
	case KindUser:
		if e.User != nil {
			return e.User.RealmID
		}
	case KindAdmin:
		if e.Admin != nil {
			return e.Admin.RealmID
		}
	}
	return ""
}

// EventType returns the native user event type, if present.
func (e Envelope) EventType() string {
	if e.Kind == KindUser && e.User != nil {
		return e.User.Type
	}
	return ""
}

// actor returns the administrator of the selected event, when available.
func (e Envelope) actor() *Actor {
	if e.Kind == KindAdmin && e.Admin != nil {
		return e.Admin.Actor
	}
	return nil
}

// ActorRealmID returns the administrator's authentication realm.
func (e Envelope) ActorRealmID() string {
	if actor := e.actor(); actor != nil {
		return actor.RealmID
	}
	return ""
}

// IdentityRealm returns the realm in which the user ID is meaningful.
func (e Envelope) IdentityRealm() string {
	if e.Kind == KindAdmin {
		return e.ActorRealmID()
	}
	return e.RealmID()
}

// UserID returns the user or administrator associated with the event.
func (e Envelope) UserID() string {
	if e.Kind == KindUser && e.User != nil {
		return e.User.UserID
	}
	if actor := e.actor(); actor != nil {
		return actor.UserID
	}
	return ""
}

// ClientID returns the client associated with the acting identity.
func (e Envelope) ClientID() string {
	if e.Kind == KindUser && e.User != nil {
		return e.User.ClientID
	}
	if actor := e.actor(); actor != nil {
		return actor.ClientID
	}
	return ""
}

// Address returns the reported IP, canonical after normalization.
func (e Envelope) Address() string {
	if e.Kind == KindUser && e.User != nil {
		return e.User.IP
	}
	if actor := e.actor(); actor != nil {
		return actor.IP
	}
	return ""
}

// IPAddress returns the parsed address of a normalized envelope, or an invalid address if absent.
func (e Envelope) IPAddress() netip.Addr {
	ip, _ := netip.ParseAddr(e.Address())
	return ip
}

// ErrorCode returns the native event error, when present.
func (e Envelope) ErrorCode() string {
	if e.Kind == KindUser && e.User != nil {
		return e.User.Error
	}
	if e.Kind == KindAdmin && e.Admin != nil {
		return e.Admin.Error
	}
	return ""
}

// OperationType returns the native administrative operation.
func (e Envelope) OperationType() string {
	if e.Kind == KindAdmin && e.Admin != nil {
		return e.Admin.OperationType
	}
	return ""
}

// ResourceType returns the affected administrative resource category.
func (e Envelope) ResourceType() string {
	if e.Kind == KindAdmin && e.Admin != nil {
		return e.Admin.ResourceType
	}
	return ""
}

// ResourcePath returns the affected administrative resource path.
func (e Envelope) ResourcePath() string {
	if e.Kind == KindAdmin && e.Admin != nil {
		return e.Admin.ResourcePath
	}
	return ""
}
