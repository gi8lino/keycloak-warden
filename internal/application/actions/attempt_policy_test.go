package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestStatusAfterFailure(t *testing.T) {
	t.Parallel()

	t.Run("continues below the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, model.DeliveryRetrying, StatusAfterFailure(1, 3))
	})

	t.Run("exhausts at the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, model.DeliveryExhausted, StatusAfterFailure(3, 3))
	})

	t.Run("exhausts above the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, model.DeliveryExhausted, StatusAfterFailure(4, 3))
	})
}
