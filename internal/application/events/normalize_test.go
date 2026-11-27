package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userEnvelope builds an independent user event fixture.
func userEnvelope() Envelope {
	return Envelope{
		Version:   SchemaVersion,
		ID:        "user-event",
		Source:    SourceKeycloak,
		Kind:      KindUser,
		Timestamp: time.Now(),
		User: &UserEvent{
			Type:    TypeLoginError,
			RealmID: "hq",
			IP:      "::ffff:203.0.113.1",
			Error:   "invalid_user_credentials",
		},
	}
}

// adminEnvelope builds an independent administrative event fixture.
func adminEnvelope() Envelope {
	return Envelope{
		Version:   SchemaVersion,
		ID:        "admin-event",
		Source:    SourceKeycloak,
		Kind:      KindAdmin,
		Timestamp: time.Now(),
		Admin: &AdminEvent{
			RealmID:       "target",
			OperationType: "CREATE",
			ResourceType:  "USER",
			ResourcePath:  "users/target-user",
			Actor: &Actor{
				RealmID: "master",
				UserID:  "administrator",
				IP:      "203.0.113.1",
			},
		},
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()

	t.Run("normalizes native user event", func(t *testing.T) {
		t.Parallel()

		event, err := Normalize(userEnvelope())

		require.NoError(t, err)
		assert.Equal(t, KindUser, event.Kind)
		assert.Equal(t, TypeLoginError, event.EventType())
		assert.Equal(t, "203.0.113.1", event.Address())
		assert.Equal(t, "hq", event.IdentityRealm())
	})

	t.Run("normalizes administrative actor separately from target", func(t *testing.T) {
		t.Parallel()

		event, err := Normalize(adminEnvelope())

		require.NoError(t, err)
		assert.Equal(t, KindAdmin, event.Kind)
		assert.Empty(t, event.EventType())
		assert.Equal(t, "target", event.RealmID())
		assert.Equal(t, "master", event.IdentityRealm())
		assert.Equal(t, "administrator", event.UserID())
		assert.Equal(t, "203.0.113.1", event.Address())
		assert.Equal(t, "users/target-user", event.ResourcePath())
	})

	t.Run("accepts administrative event without actor", func(t *testing.T) {
		t.Parallel()

		envelope := adminEnvelope()
		envelope.Admin.Actor = nil
		event, err := Normalize(envelope)

		require.NoError(t, err)
		assert.Empty(t, event.IdentityRealm())
		assert.Empty(t, event.UserID())
		assert.False(t, event.IPAddress().IsValid())
	})

	t.Run("normalizes user without modifying input", func(t *testing.T) {
		t.Parallel()

		input := userEnvelope()
		event, err := Normalize(input)

		require.NoError(t, err)
		assert.Equal(t, "::ffff:203.0.113.1", input.User.IP)
		assert.Equal(t, "203.0.113.1", event.User.IP)
		assert.NotSame(t, input.User, event.User)
	})

	t.Run("normalizes actor without modifying input", func(t *testing.T) {
		t.Parallel()

		input := adminEnvelope()
		input.Admin.Actor.IP = "::ffff:203.0.113.1"
		event, err := Normalize(input)

		require.NoError(t, err)
		assert.Equal(t, "::ffff:203.0.113.1", input.Admin.Actor.IP)
		assert.Equal(t, "203.0.113.1", event.Admin.Actor.IP)
		assert.NotSame(t, input.Admin, event.Admin)
		assert.NotSame(t, input.Admin.Actor, event.Admin.Actor)
	})

	t.Run("rejects mapped multicast address", func(t *testing.T) {
		t.Parallel()

		input := userEnvelope()
		input.User.IP = "::ffff:224.0.0.1"
		_, err := Normalize(input)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects scoped actor address", func(t *testing.T) {
		t.Parallel()

		input := adminEnvelope()
		input.Admin.Actor.IP = "fe80::1%eth0"
		_, err := Normalize(input)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects two bodies", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.Admin = adminEnvelope().Admin
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects mismatched user kind", func(t *testing.T) {
		t.Parallel()

		envelope := adminEnvelope()
		envelope.Kind = KindUser
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects mismatched admin kind", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.Kind = KindAdmin
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects missing body", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.User = nil
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects unknown kind", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.Kind = "unknown"
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects unsupported version", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.Version = SchemaVersion + 1
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects version one", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.Version = 1
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects invalid admin operation", func(t *testing.T) {
		t.Parallel()

		envelope := adminEnvelope()
		envelope.Admin.OperationType = "UNKNOWN"
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects missing user type", func(t *testing.T) {
		t.Parallel()

		envelope := userEnvelope()
		envelope.User.Type = ""
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})

	t.Run("rejects invalid actor IP", func(t *testing.T) {
		t.Parallel()

		envelope := adminEnvelope()
		envelope.Admin.Actor.IP = "invalid"
		_, err := Normalize(envelope)

		require.ErrorIs(t, err, ErrInvalidEvent)
	})
}

func TestEnvelopeJSON(t *testing.T) {
	t.Parallel()

	t.Run("decodes user contract with null identity", func(t *testing.T) {
		t.Parallel()

		const body = `{"schemaVersion":2,"id":"login-event","source":"keycloak","kind":"user","timestamp":"2026-11-27T10:00:00Z","user":{"type":"LOGIN_ERROR","realmId":"hq","clientId":"app","userId":null,"ipAddress":"::ffff:203.0.113.1","error":"invalid_user_credentials"}}`
		var envelope Envelope
		require.NoError(t, json.Unmarshal([]byte(body), &envelope))
		event, err := Normalize(envelope)

		require.NoError(t, err)
		assert.Equal(t, "203.0.113.1", event.Address())
		assert.Empty(t, event.UserID())
		assert.Nil(t, envelope.Admin)
	})

	t.Run("decodes admin contract with nested actor", func(t *testing.T) {
		t.Parallel()

		const body = `{"schemaVersion":2,"id":"admin-event","source":"keycloak","kind":"admin","timestamp":"2026-11-27T10:00:00Z","admin":{"realmId":"hq","operationType":"CREATE","resourceType":"USER","resourcePath":"users/new-user","actor":{"realmId":"master","clientId":"admin-client","userId":"admin","ipAddress":"203.0.113.1"},"error":null}}`
		var envelope Envelope
		require.NoError(t, json.Unmarshal([]byte(body), &envelope))
		event, err := Normalize(envelope)

		require.NoError(t, err)
		assert.Equal(t, "master", event.ActorRealmID())
		assert.Equal(t, "admin-client", event.ClientID())
		assert.Equal(t, "hq", event.RealmID())
		assert.Nil(t, envelope.User)
	})
}

func TestValidIdentifier(t *testing.T) {
	t.Parallel()

	t.Run("accepts uppercase letters digits and underscores", func(t *testing.T) {
		t.Parallel()

		assert.True(t, ValidIdentifier("LOGIN_ERROR_2"))
	})

	t.Run("accepts single uppercase letter", func(t *testing.T) {
		t.Parallel()

		assert.True(t, ValidIdentifier("A"))
	})

	t.Run("accepts maximum length", func(t *testing.T) {
		t.Parallel()

		assert.True(t, ValidIdentifier(strings.Repeat("A", 128)))
	})

	t.Run("rejects empty identifier", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier(""))
	})

	t.Run("rejects oversized identifier", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier(strings.Repeat("A", 129)))
	})

	t.Run("rejects initial digit", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier("1LOGIN"))
	})

	t.Run("rejects initial underscore", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier("_LOGIN"))
	})

	t.Run("rejects lowercase letters", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier("LOGIN_error"))
	})

	t.Run("rejects punctuation", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier("LOGIN-ERROR"))
	})

	t.Run("rejects whitespace", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier("LOGIN ERROR"))
	})

	t.Run("rejects non ASCII letters", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidIdentifier("LOGIN_Ä"))
	})
}

func TestValidUserType(t *testing.T) {
	t.Parallel()

	t.Run("accepts native user event", func(t *testing.T) {
		t.Parallel()

		assert.True(t, ValidUserType(TypeLoginError))
	})

	t.Run("rejects synthetic admin event", func(t *testing.T) {
		t.Parallel()

		assert.False(t, ValidUserType("ADMIN"))
	})
}
