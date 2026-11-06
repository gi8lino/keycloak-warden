package ipaddress

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseUnicast(t *testing.T) {
	t.Parallel()

	t.Run("mapped multicast is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := ParseUnicast("::ffff:224.0.0.1")

		require.Error(t, err)
	})

	t.Run("mapped unspecified address is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := ParseUnicast("::ffff:0.0.0.0")

		require.Error(t, err)
	})

	t.Run("mapped unicast is canonicalized", func(t *testing.T) {
		t.Parallel()

		ip, err := ParseUnicast("::ffff:203.0.113.10")

		require.NoError(t, err)
		assert.Equal(t, "203.0.113.10", ip.String())
	})
}
