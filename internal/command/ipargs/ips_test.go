package ipargs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts public IPv4 address", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, Validate("203.0.113.10"))
	})

	t.Run("accepts IPv6 address", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, Validate("2001:db8::10"))
	})

	t.Run("rejects blank input", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate(""), "invalid IP address")
	})

	t.Run("rejects hostnames", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate("example.org"), "invalid IP address")
	})

	t.Run("rejects unspecified addresses", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate("0.0.0.0"), "invalid IP address")
	})

	t.Run("rejects mapped unspecified addresses", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate("::ffff:0.0.0.0"), "invalid IP address")
	})

	t.Run("rejects mapped multicast addresses", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate("::ffff:224.0.0.1"), "invalid IP address")
	})

	t.Run("rejects multicast addresses", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate("ff02::1"), "invalid IP address")
	})

	t.Run("rejects IPv6 zone IDs", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, Validate("fe80::1%eth0"), "invalid IP address")
	})
}

func TestUnique(t *testing.T) {
	t.Parallel()

	t.Run("keeps distinct addresses in argument order", func(t *testing.T) {
		t.Parallel()

		ips, err := Unique([]string{"203.0.113.10", "2001:db8::10", "203.0.113.20"})

		require.NoError(t, err)
		assert.Equal(t, []string{"203.0.113.10", "2001:db8::10", "203.0.113.20"}, ips)
	})

	t.Run("deduplicates mapped IPv4 and canonical IPv6", func(t *testing.T) {
		t.Parallel()

		ips, err := Unique([]string{"::ffff:203.0.113.10", "203.0.113.10", "2001:0db8:0:0::1", "2001:db8::1"})

		require.NoError(t, err)
		assert.Equal(t, []string{"203.0.113.10", "2001:db8::1"}, ips)
	})

	t.Run("rejects missing addresses", func(t *testing.T) {
		t.Parallel()

		_, err := Unique(nil)

		require.ErrorContains(t, err, "at least one IP address")
	})

	t.Run("rejects one invalid address without returning partial results", func(t *testing.T) {
		t.Parallel()

		ips, err := Unique([]string{"203.0.113.10", "not-an-ip", "203.0.113.20"})

		require.ErrorContains(t, err, "not-an-ip")
		assert.Nil(t, ips)
	})
}
