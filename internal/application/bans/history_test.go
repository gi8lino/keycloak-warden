package bans

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryOffset(t *testing.T) {
	t.Parallel()

	t.Run("first page", func(t *testing.T) {
		t.Parallel()
		offset, err := HistoryOffset(1)
		require.NoError(t, err)
		assert.Zero(t, offset)
	})

	t.Run("hundredth page", func(t *testing.T) {
		t.Parallel()
		offset, err := HistoryOffset(100)
		require.NoError(t, err)
		assert.EqualValues(t, 1584, offset)
	})

	t.Run("zero page", func(t *testing.T) {
		t.Parallel()
		_, err := HistoryOffset(0)
		require.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("negative page", func(t *testing.T) {
		t.Parallel()
		_, err := HistoryOffset(-1)
		require.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("overflowing page", func(t *testing.T) {
		t.Parallel()
		_, err := HistoryOffset(math.MaxInt)
		require.ErrorIs(t, err, ErrInvalid)
	})
}
