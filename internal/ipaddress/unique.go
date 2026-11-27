package ipaddress

import (
	"errors"
	"fmt"
)

// Unique validates all inputs before returning canonical, deduplicated IP addresses.
func Unique(values []string) (addresses []string, err error) {
	if len(values) == 0 {
		return nil, errors.New("at least one IP address is required")
	}

	addresses = make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		address, err := ParseUnicast(value)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", value, err)
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
