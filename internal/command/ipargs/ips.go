// Package ipargs validates and normalizes positional IP addresses for operator commands.
package ipargs

import (
	"errors"
	"fmt"
	"github.com/gi8lino/keycloak-warden/internal/ipaddress"
	"net/netip"
)

// Validate requires a single unicast IPv4 or IPv6 address without a zone.
func Validate(value string) error {
	_, err := parse(value)
	return err
}

// Unique validates all inputs before returning canonical, deduplicated IP addresses.
func Unique(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one IP address is required")
	}

	addresses := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		address, err := parse(value)
		if err != nil {
			return nil, err
		}

		canonical := address.String()
		if _, exists := seen[canonical]; exists {
			continue
		}

		seen[canonical] = struct{}{}
		addresses = append(addresses, canonical)
	}
	return addresses, nil
}

// parse returns a canonical unicast address with an operator-facing input error.
func parse(value string) (netip.Addr, error) {
	address, err := ipaddress.ParseUnicast(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q: %w", value, err)
	}
	return address, nil
}
