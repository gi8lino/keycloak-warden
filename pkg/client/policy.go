package client

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/containeroo/httpkit/prefix"

	"github.com/gi8lino/keycloak-warden/internal/urlpolicy"
)

const (
	// DefaultMaxResponseBytes limits successful administrative API responses to one MiB.
	DefaultMaxResponseBytes = 1 << 20
	// DefaultRequestTimeout bounds ordinary administrative HTTP requests.
	DefaultRequestTimeout = 10 * time.Second
	// DefaultMaintenanceTimeout exceeds the server's 30-second maintenance deadline.
	DefaultMaintenanceTimeout = 35 * time.Second
)

// ValidateMaxResponseBytes requires a positive limit with room for a one-byte overflow sentinel.
func ValidateMaxResponseBytes(limit int) error {
	if limit <= 0 || int64(limit) == math.MaxInt64 {
		return errors.New("maximum response bytes must be positive and less than MaxInt64")
	}
	return nil
}

// parseApplicationURL validates and normalizes an administrative API base URL.
func parseApplicationURL(address string, allowInsecureHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid application-url: %w", err)
	}

	if !isValidBaseURL(parsed) {
		return nil, errors.New("application-url must have a host and no credentials, query, fragment, or encoded path")
	}

	if !urlpolicy.AllowedTransport(parsed) && (!allowInsecureHTTP || parsed.Scheme != "http") {
		return nil, errors.New("application-url requires HTTPS unless connecting to loopback")
	}

	if err := prefix.ValidateRoutePrefix(parsed.Path); err != nil {
		return nil, fmt.Errorf("invalid application-url route prefix: %w", err)
	}

	parsed.Path = prefix.NormalizeRoutePrefix(parsed.Path)
	return parsed, nil
}

// isValidBaseURL rejects URL components unrelated to the administrative API base path.
func isValidBaseURL(u *url.URL) bool {
	return u.Hostname() != "" &&
		u.User == nil &&
		u.Opaque == "" &&
		u.Fragment == "" &&
		u.RawQuery == "" &&
		!u.ForceQuery &&
		u.RawPath == "" &&
		u.EscapedPath() == u.Path
}
