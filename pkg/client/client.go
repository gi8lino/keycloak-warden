// Package client provides an HTTP client for the Warden administration API.
package client

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Option configures the administration API client.
type Option func(*clientOptions)

// clientOptions holds transport policy and request limits for administrative connections.
type clientOptions struct {
	// allowInsecureHTTP permits plain HTTP for non-loopback application URLs.
	allowInsecureHTTP bool
	// maxAdminResponseBytes bounds successful response bodies in bytes.
	maxAdminResponseBytes int
	// clientTimeout bounds the total duration of an ordinary administrative HTTP request.
	clientTimeout time.Duration
	// maintenanceClientTimeout bounds maintenance requests independently of ordinary requests.
	maintenanceClientTimeout time.Duration
}

// WithAllowInsecureHTTP allows unencrypted HTTP connections to non-loopback hosts.
// Use this only for trusted network paths, such as a restricted Kubernetes Service.
// It does not change HTTPS certificate verification or redirect handling.
func WithAllowInsecureHTTP() Option {
	return func(options *clientOptions) {
		options.allowInsecureHTTP = true
	}
}

// WithRequestTimeout sets a positive timeout for ordinary administrative requests (default 10 seconds).
func WithRequestTimeout(timeout time.Duration) Option {
	return func(options *clientOptions) {
		options.clientTimeout = timeout
	}
}

// WithMaintenanceTimeout sets a positive timeout for maintenance requests (default 35 seconds).
// Allow enough time for the server's maintenance deadline (currently 30 seconds).
func WithMaintenanceTimeout(timeout time.Duration) Option {
	return func(options *clientOptions) {
		options.maintenanceClientTimeout = timeout
	}
}

// WithMaxResponseBytes sets a positive maximum size for successful response bodies (default one MiB).
func WithMaxResponseBytes(limit int) Option {
	return func(options *clientOptions) {
		options.maxAdminResponseBytes = limit
	}
}

// resolveOptions applies caller overrides once on top of the default request limits.
func resolveOptions(opts []Option) clientOptions {
	options := clientOptions{
		maxAdminResponseBytes:    DefaultMaxResponseBytes,
		clientTimeout:            DefaultRequestTimeout,
		maintenanceClientTimeout: DefaultMaintenanceTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return options
}

// validate rejects disabled deadlines and response limits that cannot include an overflow sentinel.
func (o clientOptions) validate() error {
	if o.clientTimeout <= 0 {
		return errors.New("request timeout must be positive")
	}

	if o.maintenanceClientTimeout <= 0 {
		return errors.New("maintenance timeout must be positive")
	}

	return ValidateMaxResponseBytes(o.maxAdminResponseBytes)
}

// Client authenticates administrative requests against the running Warden server.
type Client struct {
	// options contains the validated immutable request limits and transport policy.
	options clientOptions
	// url is the validated administrative API base URL, including its optional route prefix.
	url *url.URL
	// token authenticates requests to the administrative API.
	token string
	// http executes requests with redirects disabled; each operation bounds its own context.
	http *http.Client
}

// New validates the application URL, bearer token, and request limits before making any request.
// Non-loopback HTTP requires WithAllowInsecureHTTP.
func New(address, token string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("admin-token is required")
	}

	options := resolveOptions(opts)
	if err := options.validate(); err != nil {
		return nil, err
	}

	parsed, err := parseApplicationURL(address, options.allowInsecureHTTP)
	if err != nil {
		return nil, err
	}

	return &Client{
		options: options,
		url:     parsed,
		token:   token,
		http: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// ValidateURL checks an application API base URL, optionally with a route prefix.
// Pass WithAllowInsecureHTTP to permit non-loopback HTTP URLs.
func ValidateURL(address string, opts ...Option) error {
	_, err := parseApplicationURL(address, resolveOptions(opts).allowInsecureHTTP)
	return err
}
