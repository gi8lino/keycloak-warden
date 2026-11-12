// Package client calls the Warden administration API without access to its internal storage or services.
package client

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/containeroo/httpkit/prefix"
)

// Client authenticates administrative requests against the running Warden server.
type Client struct {
	// url is the validated administrative API base URL, including its optional route prefix.
	url *url.URL
	// token authenticates requests to the administrative API.
	token string
	// http executes requests with redirects disabled; each operation bounds its own context.
	http *http.Client
}

// New validates the application URL and bearer token before making any request.
func New(address, token string) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("admin-token is required")
	}
	parsed, err := parseApplicationURL(address)
	if err != nil {
		return nil, err
	}
	return &Client{
		url:   parsed,
		token: token,
		http: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// ValidateURL checks an application API base URL, optionally with a route prefix.
func ValidateURL(address string) error {
	_, err := parseApplicationURL(address)
	return err
}

// parseApplicationURL validates a URL and its optional application route prefix.
func parseApplicationURL(address string) (parsed *url.URL, err error) {
	parsed, err = url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid application-url: %w", err)
	}

	if !isValidBaseURL(parsed) {
		return nil, errors.New("application-url must have a host and no credentials, query, fragment, or encoded path")
	}

	if !allowedTransport(parsed) {
		return nil, errors.New("application-url requires HTTPS unless connecting to loopback")
	}

	if err := prefix.ValidateRoutePrefix(parsed.Path); err != nil {
		return nil, fmt.Errorf("invalid application-url route prefix: %w", err)
	}
	parsed.Path = prefix.NormalizeRoutePrefix(parsed.Path)
	return parsed, nil
}

// isValidBaseURL rejects URL components unrelated to the API base path.
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

// allowedTransport requires HTTPS, except for explicit loopback HTTP endpoints.
func allowedTransport(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
