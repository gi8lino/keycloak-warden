package client

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateMaxResponseBytes(t *testing.T) {
	t.Parallel()

	t.Run("accepts the client default", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateMaxResponseBytes(DefaultMaxResponseBytes))
	})

	t.Run("accepts the minimum positive value", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateMaxResponseBytes(1))
	})

	t.Run("rejects zero", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateMaxResponseBytes(0), "must be positive")
	})

	t.Run("rejects negative values", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateMaxResponseBytes(-1), "must be positive")
	})

	t.Run("rejects a limit that overflows the sentinel", func(t *testing.T) {
		t.Parallel()

		if strconv.IntSize != 64 {
			t.Skip("MaxInt does not overflow int64 on 32-bit systems")
		}

		require.ErrorContains(t, ValidateMaxResponseBytes(math.MaxInt), "less than MaxInt64")
	})

	t.Run("accepts the largest sentinel-safe limit", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateMaxResponseBytes(math.MaxInt-1))
	})
}
