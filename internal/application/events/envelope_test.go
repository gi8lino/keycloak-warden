package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEnvelopeConstants protects the Snitch wire values used for detection.
func TestEnvelopeConstants(t *testing.T) {
	t.Parallel()

	t.Run("schema version", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 2, SchemaVersion)
	})

	t.Run("Keycloak source", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "keycloak", SourceKeycloak)
	})

	t.Run("login error type", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "LOGIN_ERROR", TypeLoginError)
	})
}

// TestEnvelopeAccessors verifies that missing event bodies and actors are safe to inspect.
func TestEnvelopeAccessors(t *testing.T) {
	t.Parallel()

	t.Run("empty envelope", func(t *testing.T) {
		t.Parallel()

		var event Envelope
		assert.Empty(t, event.RealmID())
		assert.Empty(t, event.IdentityRealm())
		assert.Empty(t, event.EventType())
		assert.Empty(t, event.ActorRealmID())
		assert.Empty(t, event.UserID())
		assert.Empty(t, event.ClientID())
		assert.Empty(t, event.Address())
		assert.False(t, event.IPAddress().IsValid())
		assert.Empty(t, event.ErrorCode())
		assert.Empty(t, event.OperationType())
		assert.Empty(t, event.ResourceType())
		assert.Empty(t, event.ResourcePath())
	})

	t.Run("user identity", func(t *testing.T) {
		t.Parallel()

		event := Envelope{
			Kind: KindUser,
			User: &UserEvent{
				RealmID:  "hq",
				UserID:   "user",
				ClientID: "application",
				Error:    "invalid_user_credentials",
			},
		}
		assert.Equal(t, "hq", event.IdentityRealm())
		assert.Equal(t, "user", event.UserID())
		assert.Equal(t, "application", event.ClientID())
		assert.Equal(t, "invalid_user_credentials", event.ErrorCode())
		assert.Empty(t, event.ActorRealmID())
	})
}
