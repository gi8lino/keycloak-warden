package urlpolicy

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowedTransport(t *testing.T) {
	t.Parallel()

	t.Run("accepts remote HTTPS", func(t *testing.T) {
		t.Parallel()

		assert.True(t, AllowedTransport(&url.URL{Scheme: "https", Host: "warden.example.com"}))
	})

	t.Run("accepts loopback hostname HTTP", func(t *testing.T) {
		t.Parallel()

		assert.True(t, AllowedTransport(&url.URL{Scheme: "http", Host: "localhost:8081"}))
	})

	t.Run("accepts IPv4 loopback HTTP", func(t *testing.T) {
		t.Parallel()

		assert.True(t, AllowedTransport(&url.URL{Scheme: "http", Host: "127.0.0.1:8081"}))
	})

	t.Run("accepts IPv6 loopback HTTP", func(t *testing.T) {
		t.Parallel()

		assert.True(t, AllowedTransport(&url.URL{Scheme: "http", Host: "[::1]:8081"}))
	})

	t.Run("rejects remote HTTP", func(t *testing.T) {
		t.Parallel()

		assert.False(t, AllowedTransport(&url.URL{Scheme: "http", Host: "warden:8081"}))
	})

	t.Run("rejects nonloopback IPv4 HTTP", func(t *testing.T) {
		t.Parallel()

		assert.False(t, AllowedTransport(&url.URL{Scheme: "http", Host: "192.0.2.1:8081"}))
	})

	t.Run("rejects nonloopback IPv6 HTTP", func(t *testing.T) {
		t.Parallel()

		assert.False(t, AllowedTransport(&url.URL{Scheme: "http", Host: "[2001:db8::1]:8081"}))
	})

	t.Run("rejects unsupported schemes", func(t *testing.T) {
		t.Parallel()

		assert.False(t, AllowedTransport(&url.URL{Scheme: "ftp", Host: "localhost"}))
	})

	t.Run("rejects nil URL", func(t *testing.T) {
		t.Parallel()

		assert.False(t, AllowedTransport(nil))
	})
}
