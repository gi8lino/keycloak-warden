package bans

import (
	"fmt"
	"net/netip"
	"strings"
)

// Protection is an immutable collection of addresses exempt from new bans.
type Protection struct {
	// prefixes contains canonical IPv4 and IPv6 networks.
	prefixes []netip.Prefix
}

// NewProtection validates IP addresses and CIDRs before accepting configuration.
func NewProtection(values []string) (Protection, error) {
	var result Protection

	for _, value := range values {
		prefix, err := parseProtectedPrefix(value)
		if err != nil {
			return Protection{}, err
		}

		result.prefixes = append(result.prefixes, prefix)
	}

	return result, nil
}

// parseProtectedPrefix parses an IP address or CIDR into a canonical prefix.
func parseProtectedPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)

	addr, err := netip.ParseAddr(value)
	if err == nil {
		if addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid protected IP or CIDR %q", value)
		}

		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid protected IP or CIDR %q", value)
	}

	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("ambiguous mapped IPv4 CIDR %q", value)
		}

		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}

	return prefix.Masked(), nil
}

// Empty reports whether any protected addresses were configured.
func (p Protection) Empty() bool { return len(p.prefixes) == 0 }

// Contains reports whether an address is protected, including mapped IPv4 addresses.
func (p Protection) Contains(addr netip.Addr) bool {
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// Policy controls whether new bans may be created.
type Policy struct {
	// Protection exempts trusted networks from enforcement.
	Protection Protection
	// ObserveOnly records automatic threshold hits without creating enforcement state.
	ObserveOnly bool
}
