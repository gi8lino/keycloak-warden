package adminclient

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 1<<20, DefaultMaxResponseBytes)
	assert.Equal(t, 10*time.Second, DefaultRequestTimeout)
	assert.Equal(t, 35*time.Second, DefaultMaintenanceTimeout)
}

func TestValidateURL(t *testing.T) {
	t.Parallel()

	t.Run("accepts remote HTTPS", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateURL("https://warden.example.com/warden", false))
	})

	t.Run("accepts loopback HTTP", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateURL("http://127.0.0.1:8080", false))
	})

	t.Run("rejects remote HTTP by default", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateURL("http://warden.example.com", false), "HTTPS")
	})

	t.Run("accepts remote HTTP with opt-in", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, ValidateURL("http://warden.example.com", true))
	})

	t.Run("rejects unsupported schemes even with opt-in", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateURL("ftp://warden.example.com", true), "HTTPS")
	})

	t.Run("rejects credentials", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateURL("https://user:password@warden.example.com", false), "application-url")
	})

	t.Run("rejects query strings", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateURL("https://warden.example.com?token=secret", false), "application-url")
	})

	t.Run("rejects encoded paths", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateURL("https://warden.example.com/ward%65n", false), "application-url")
	})

	t.Run("rejects invalid route prefixes", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, ValidateURL("https://warden.example.com/warden/../bans", false), "route prefix")
	})
}

func TestParseApplicationURL(t *testing.T) {
	t.Parallel()

	t.Run("normalizes the route prefix", func(t *testing.T) {
		t.Parallel()

		parsed, err := ParseApplicationURL("https://warden.example.com/warden/", false)

		require.NoError(t, err)
		assert.Equal(t, "/warden", parsed.Path)
	})

	t.Run("rejects a missing host", func(t *testing.T) {
		t.Parallel()

		parsed, err := ParseApplicationURL("https:///", false)

		require.ErrorContains(t, err, "application-url")
		assert.Nil(t, parsed)
	})
}

// TestValidateMaxResponseBytes applies the same limit policy to flags and client construction.
func TestValidateMaxResponseBytes(t *testing.T) {
	t.Parallel()

	t.Run("accepts a one-byte response limit", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, ValidateMaxResponseBytes(1))
	})

	t.Run("accepts the default response limit", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, ValidateMaxResponseBytes(DefaultMaxResponseBytes))
	})

	t.Run("rejects zero", func(t *testing.T) {
		t.Parallel()
		require.ErrorContains(t, ValidateMaxResponseBytes(0), "must be positive")
	})

	t.Run("rejects negative values", func(t *testing.T) {
		t.Parallel()
		require.ErrorContains(t, ValidateMaxResponseBytes(-1), "must be positive")
	})

	t.Run("rejects the maximum signed int64", func(t *testing.T) {
		t.Parallel()
		if int64(math.MaxInt) != math.MaxInt64 {
			t.Skip("int cannot represent MaxInt64")
		}
		require.ErrorContains(t, ValidateMaxResponseBytes(math.MaxInt), "less than MaxInt64")
	})

	t.Run("accepts one less than the maximum signed int64", func(t *testing.T) {
		t.Parallel()
		if int64(math.MaxInt) != math.MaxInt64 {
			t.Skip("int cannot represent MaxInt64")
		}
		require.NoError(t, ValidateMaxResponseBytes(math.MaxInt-1))
	})
}
