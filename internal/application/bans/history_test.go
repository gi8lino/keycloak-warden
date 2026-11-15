package bans

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHistoryPage(t *testing.T) {
	t.Parallel()

	t.Run("first page", func(t *testing.T) {
		t.Parallel()
		page, err := NewHistoryPage(1, 0)
		require.NoError(t, err)
		assert.Zero(t, page.Offset)
	})

	t.Run("hundredth page", func(t *testing.T) {
		t.Parallel()
		page, err := NewHistoryPage(100, 0)
		require.NoError(t, err)
		assert.EqualValues(t, 1584, page.Offset)
	})

	t.Run("zero page", func(t *testing.T) {
		t.Parallel()
		_, err := NewHistoryPage(0, 0)
		require.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("negative page", func(t *testing.T) {
		t.Parallel()
		_, err := NewHistoryPage(-1, 0)
		require.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("overflowing page", func(t *testing.T) {
		t.Parallel()
		_, err := NewHistoryPage(math.MaxInt, 0)
		require.ErrorIs(t, err, ErrInvalid)
	})
}
