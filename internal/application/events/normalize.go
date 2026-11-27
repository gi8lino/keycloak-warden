package events

import (
	"errors"
	"strings"

	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
)

// ErrInvalidEvent identifies an event rejected by the Snitch contract.
var ErrInvalidEvent = errors.New("invalid security event")

// Normalize validates the envelope and returns an independent, canonical snapshot.
func Normalize(p Envelope) (Envelope, error) {
	if !validEnvelope(p) || !p.validPayload() {
		return Envelope{}, ErrInvalidEvent
	}

	switch p.Kind {
	case KindUser:
		return normalizeUser(p)
	case KindAdmin:
		return normalizeAdmin(p)
	default:
		return Envelope{}, ErrInvalidEvent
	}
}

// normalizeUser validates and copies the user payload.
func normalizeUser(p Envelope) (Envelope, error) {
	user := *p.User
	if !validUser(user) {
		return Envelope{}, ErrInvalidEvent
	}

	address, err := canonicalAddress(user.IP)
	if err != nil {
		return Envelope{}, err
	}
	user.IP = address
	p.User = &user
	return p, nil
}

// normalizeAdmin validates and copies the administrative payload and actor.
func normalizeAdmin(p Envelope) (Envelope, error) {
	admin := *p.Admin
	if !validAdmin(admin) {
		return Envelope{}, ErrInvalidEvent
	}

	if admin.Actor != nil {
		actor := *admin.Actor
		address, err := canonicalAddress(actor.IP)
		if err != nil {
			return Envelope{}, err
		}
		actor.IP = address
		admin.Actor = &actor
	}
	p.Admin = &admin
	return p, nil
}

// canonicalAddress preserves missing addresses and canonicalizes valid unicast addresses.
func canonicalAddress(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	ip, err := ipaddress.ParseUnicast(value)
	if err != nil {
		return "", ErrInvalidEvent
	}
	return ip.String(), nil
}

// validEnvelope checks shared identity and schema metadata.
func validEnvelope(p Envelope) bool {
	if p.Source != SourceKeycloak || p.Version != SchemaVersion {
		return false
	}
	return strings.TrimSpace(p.ID) != "" && len(p.ID) <= 128 && !p.Timestamp.IsZero()
}

// validUser checks the native type and bounded user metadata.
func validUser(p UserEvent) bool {
	if !ValidUserType(p.Type) {
		return false
	}
	return validIdentity(p.RealmID, p.UserID, p.ClientID) && len(p.Error) <= 512
}

// validAdmin checks the target realm, operation, resource and actor metadata.
func validAdmin(p AdminEvent) bool {
	if strings.TrimSpace(p.RealmID) == "" || strings.TrimSpace(p.ResourceType) == "" {
		return false
	}
	if !ValidOperation(p.OperationType) || !validAdminLengths(p) {
		return false
	}
	return p.Actor == nil || validIdentity(p.Actor.RealmID, p.Actor.UserID, p.Actor.ClientID)
}

// validAdminLengths bounds administrative metadata before persistence.
func validAdminLengths(p AdminEvent) bool {
	if len(p.RealmID) > 256 || len(p.ResourceType) > 128 {
		return false
	}
	return len(p.ResourcePath) <= 2048 && len(p.Error) <= 512
}

// validIdentity bounds realm-scoped identity metadata.
func validIdentity(realm, user, client string) bool {
	return len(realm) <= 256 && len(user) <= 256 && len(client) <= 256
}

// ValidIdentifier checks the syntax of a native event or resource identifier.
func ValidIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	if value[0] < 'A' || value[0] > 'Z' {
		return false
	}

	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// ValidUserType checks the native user-event identifier syntax.
func ValidUserType(value string) bool {
	return value != "ADMIN" && ValidIdentifier(value)
}

// ValidOperation reports whether the operation is a native Keycloak administrative operation.
func ValidOperation(operation string) bool {
	switch operation {
	case "CREATE", "UPDATE", "DELETE", "ACTION":
		return true
	default:
		return false
	}
}
