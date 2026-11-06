// Package ipaddress validates canonical addresses used by detection and operator commands.
package ipaddress

import (
	"errors"
	"net/netip"
)

// ParseUnicast canonicalizes IPv4-mapped addresses before rejecting zones and non-unicast IPs.
func ParseUnicast(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errors.New("expected a single unicast IPv4 or IPv6 address")
	}

	address = address.Unmap()
	if address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, errors.New("expected a single unicast IPv4 or IPv6 address")
	}
	return address, nil
}
