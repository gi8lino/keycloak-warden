package deliverystate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusValid(t *testing.T) {
	t.Parallel()

	t.Run("accepts pending", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StatusPending.Valid())
	})

	t.Run("accepts retrying", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StatusRetrying.Valid())
	})

	t.Run("accepts delivered", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StatusDelivered.Valid())
	})

	t.Run("accepts exhausted", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StatusExhausted.Valid())
	})

	t.Run("accepts superseded", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StatusSuperseded.Valid())
	})

	t.Run("rejects unknown", func(t *testing.T) {
		t.Parallel()
		assert.False(t, Status("unknown").Valid())
	})
}

func TestOutcomeValid(t *testing.T) {
	t.Parallel()

	t.Run("accepts succeeded", func(t *testing.T) {
		t.Parallel()
		assert.True(t, OutcomeSucceeded.Valid())
	})

	t.Run("accepts failed", func(t *testing.T) {
		t.Parallel()
		assert.True(t, OutcomeFailed.Valid())
	})

	t.Run("rejects unknown", func(t *testing.T) {
		t.Parallel()
		assert.False(t, Outcome("unknown").Valid())
	})
}
