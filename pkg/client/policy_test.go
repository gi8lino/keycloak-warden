package client

import (
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

func TestParseApplicationURL(t *testing.T) {
	t.Parallel()

	t.Run("normalizes the route prefix", func(t *testing.T) {
		t.Parallel()

		parsed, err := parseApplicationURL("https://warden.example.com/warden/", false)

		require.NoError(t, err)
		assert.Equal(t, "/warden", parsed.Path)
	})

	t.Run("rejects a missing host", func(t *testing.T) {
		t.Parallel()

		parsed, err := parseApplicationURL("https:///", false)

		require.ErrorContains(t, err, "application-url")
		assert.Nil(t, parsed)
	})
}
