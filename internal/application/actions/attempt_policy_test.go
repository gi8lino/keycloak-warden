package actions

import (
	"testing"

	"github.com/gi8lino/keycloak-warden/pkg/deliverystate"
	"github.com/stretchr/testify/assert"
)

func TestStatusAfterFailure(t *testing.T) {
	t.Parallel()

	t.Run("continues below the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, deliverystate.StatusRetrying, StatusAfterFailure(1, 3))
	})

	t.Run("exhausts at the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, deliverystate.StatusExhausted, StatusAfterFailure(3, 3))
	})

	t.Run("exhausts above the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, deliverystate.StatusExhausted, StatusAfterFailure(4, 3))
	})
}
