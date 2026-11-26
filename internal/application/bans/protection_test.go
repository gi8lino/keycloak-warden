package bans

import (
	"net/netip"
	"testing"
)

func TestProtection(t *testing.T) {
	t.Parallel()

	t.Run("normalizes addresses and prefixes", func(t *testing.T) {
		t.Parallel()
		p, err := NewProtection([]string{"192.0.2.9", "203.0.113.19/24", "2001:db8:1::/48", "::ffff:198.51.100.0/120"})
		if err != nil {
			t.Fatal(err)
		}
		if !p.Contains(netip.MustParseAddr("::ffff:192.0.2.9")) || !p.Contains(netip.MustParseAddr("203.0.113.50")) || !p.Contains(netip.MustParseAddr("2001:db8:1::f")) || !p.Contains(netip.MustParseAddr("198.51.100.99")) {
			t.Fatal("expected matching protected addresses")
		}
		if p.Contains(netip.MustParseAddr("192.0.2.10")) || p.Contains(netip.MustParseAddr("2001:db8:2::1")) {
			t.Fatal("unexpected protection outside the configured networks")
		}
	})

	t.Run("rejects invalid networks", func(t *testing.T) {
		t.Parallel()
		if _, err := NewProtection([]string{"192.0.2.0/33"}); err == nil {
			t.Fatal("expected invalid CIDR error")
		}
	})

	t.Run("rejects scoped addresses", func(t *testing.T) {
		t.Parallel()
		if _, err := NewProtection([]string{"fe80::1%eth0"}); err == nil {
			t.Fatal("expected scoped address error")
		}
	})

	t.Run("rejects ambiguous mapped networks", func(t *testing.T) {
		t.Parallel()
		if _, err := NewProtection([]string{"::ffff:192.0.2.0/80"}); err == nil {
			t.Fatal("expected ambiguous mapped CIDR error")
		}
	})

	t.Run("empty protection matches nothing", func(t *testing.T) {
		t.Parallel()
		var p Protection
		if p.Contains(netip.MustParseAddr("192.0.2.1")) {
			t.Fatal("unexpected protection")
		}
	})
}
