// Package urlpolicy defines the shared transport policy for configured HTTP destinations.
package urlpolicy

import "net/url"

// AllowedTransport permits HTTPS everywhere and HTTP only on explicit loopback hosts.
// Callers must separately validate the URL shape required by their endpoint.
func AllowedTransport(u *url.URL) bool {
	if u == nil {
		return false
	}

	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopback(u.Hostname())
	default:
		return false
	}
}

// isLoopback identifies hosts permitted to use plaintext HTTP for local development.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
