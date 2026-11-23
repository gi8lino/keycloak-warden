package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEventConstants protects the Snitch wire values used for detection.
func TestEventConstants(t *testing.T) {
	t.Parallel()

	t.Run("Keycloak source", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "keycloak", SourceKeycloak)
	})

	t.Run("login error type", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "LOGIN_ERROR", KindLoginError)
	})
}
