package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeliveryStatusValid(t *testing.T) {
	t.Parallel()

	t.Run("accepts pending", func(t *testing.T) {
		t.Parallel()
		assert.True(t, DeliveryPending.Valid())
	})

	t.Run("accepts retrying", func(t *testing.T) {
		t.Parallel()
		assert.True(t, DeliveryRetrying.Valid())
	})

	t.Run("accepts delivered", func(t *testing.T) {
		t.Parallel()
		assert.True(t, DeliveryDelivered.Valid())
	})

	t.Run("accepts exhausted", func(t *testing.T) {
		t.Parallel()
		assert.True(t, DeliveryExhausted.Valid())
	})

	t.Run("accepts superseded", func(t *testing.T) {
		t.Parallel()
		assert.True(t, DeliverySuperseded.Valid())
	})

	t.Run("rejects unknown", func(t *testing.T) {
		t.Parallel()
		assert.False(t, DeliveryStatus("unknown").Valid())
	})
}

func TestAttemptOutcomeValid(t *testing.T) {
	t.Parallel()

	t.Run("accepts succeeded", func(t *testing.T) {
		t.Parallel()
		assert.True(t, AttemptSucceeded.Valid())
	})

	t.Run("accepts failed", func(t *testing.T) {
		t.Parallel()
		assert.True(t, AttemptFailed.Valid())
	})

	t.Run("rejects unknown", func(t *testing.T) {
		t.Parallel()
		assert.False(t, AttemptOutcome("unknown").Valid())
	})
}
