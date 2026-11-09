// Package adminclient calls the running Warden application API without direct SQLite access.
package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/containeroo/httpkit/prefix"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/urlpolicy"
)

const (
	maxAdminResponseBytes = 1 << 20
	clientTimeout         = 10 * time.Second
)

// Client authenticates administrative requests against the running Warden server.
type Client struct {
	// url is the validated administrative API origin.
	url *url.URL
	// token authenticates requests to the administrative API.
	token string
	// http enforces outbound timeouts and redirect policy.
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
			Timeout:       clientTimeout,
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

	if !urlpolicy.AllowedTransport(parsed) {
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

// createBanRequest is the JSON body used by the application ban endpoint.
type createBanRequest struct {
	// IPAddress is the canonical address selected by the operation.
	IPAddress string `json:"ipAddress"`
	// Duration specifies how long the requested manual block should last.
	Duration string `json:"duration"`
	// Reason records the operator explanation for the requested block.
	Reason string `json:"reason"`
}

// Ban requests one operator-initiated ban from the running application server.
func (c *Client) Ban(ctx context.Context, request bans.Request) (bans.Ban, error) {
	return c.request(ctx, http.MethodPost, "/bans", createBanRequest{
		IPAddress: request.IP,
		Duration:  request.Duration.String(),
		Reason:    request.Reason,
	})
}

// Unban removes all active ban sources using a decision ID or canonical IP address.
func (c *Client) Unban(ctx context.Context, identifier string) (bans.Ban, error) {
	if strings.TrimSpace(identifier) == "" {
		return bans.Ban{}, errors.New("decision ID or IP address is required")
	}

	if address, err := netip.ParseAddr(identifier); err == nil {
		list, err := c.List(ctx)
		if err != nil {
			return bans.Ban{}, err
		}

		identifier = ""
		for _, view := range list {
			if view.Decision.IP == address.Unmap().String() {
				identifier = view.Decision.ID
				break
			}
		}
		if identifier == "" {
			return bans.Ban{}, bans.ErrNotFound
		}
	}

	return c.request(ctx, http.MethodDelete, "/bans/"+url.PathEscape(identifier), nil)
}

// List fetches effective bans with their automatic and manual sources.
func (c *Client) List(ctx context.Context) ([]bans.Ban, error) {
	var list []bans.Ban
	if err := c.do(ctx, http.MethodGet, "/bans", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// request issues one administrative operation and decodes a single ban response.
func (c *Client) request(ctx context.Context, method, path string, payload any) (bans.Ban, error) {
	var result bans.Ban
	if err := c.do(ctx, method, path, payload, &result); err != nil {
		return bans.Ban{}, err
	}
	return result, nil
}

// do performs an authenticated administrative request with bounded JSON response decoding.
func (c *Client) do(
	ctx context.Context,
	method, path string,
	payload any,
	target any,
) error {
	var body io.Reader

	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}

	destination := *c.url
	destination.Path = c.url.Path + path

	req, err := http.NewRequestWithContext(ctx, method, destination.String(), body)
	if err != nil {
		return fmt.Errorf("construct administrative request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("administrative request failed: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		message, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("application HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(message)))
	}

	// Read one byte beyond the limit so an oversized response is never accepted.
	data, err := io.ReadAll(io.LimitReader(res.Body, maxAdminResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read application response: %w", err)
	}
	if len(data) > maxAdminResponseBytes {
		return fmt.Errorf("application response exceeds %d bytes", maxAdminResponseBytes)
	}

	// Unmarshal rejects trailing JSON documents and any non-whitespace suffix.
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode application response: %w", err)
	}

	return nil
}
