package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecisionStateValid(t *testing.T) {
	t.Parallel()

	t.Run("banned is valid", func(t *testing.T) {
		t.Parallel()

		assert.True(t, DecisionBanned.Valid())
	})

	t.Run("unbanned is valid", func(t *testing.T) {
		t.Parallel()

		assert.True(t, DecisionUnbanned.Valid())
	})

	t.Run("empty is invalid", func(t *testing.T) {
		t.Parallel()

		assert.False(t, DecisionState("").Valid())
	})

	t.Run("unsupported value is invalid", func(t *testing.T) {
		t.Parallel()

		assert.False(t, DecisionState("pending").Valid())
	})
}
