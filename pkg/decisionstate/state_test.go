package decisionstate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStateValid(t *testing.T) {
	t.Parallel()

	t.Run("banned is valid", func(t *testing.T) {
		t.Parallel()

		assert.True(t, StateBanned.Valid())
	})

	t.Run("unbanned is valid", func(t *testing.T) {
		t.Parallel()

		assert.True(t, StateUnbanned.Valid())
	})

	t.Run("empty is invalid", func(t *testing.T) {
		t.Parallel()

		assert.False(t, State("").Valid())
	})

	t.Run("unsupported value is invalid", func(t *testing.T) {
		t.Parallel()

		assert.False(t, State("pending").Valid())
	})
}
