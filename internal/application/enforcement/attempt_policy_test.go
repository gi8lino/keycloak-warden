package enforcement

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestAttemptLimit(t *testing.T) {
	t.Parallel()

	t.Run("continues below the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, model.DeliveryRetrying, AttemptLimit(3).AfterFailure(1))
	})

	t.Run("exhausts at the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, model.DeliveryExhausted, AttemptLimit(3).AfterFailure(3))
	})

	t.Run("exhausts above the limit", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, model.DeliveryExhausted, AttemptLimit(3).AfterFailure(4))
	})
}
