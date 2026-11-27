package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// do performs an authenticated administrative request with bounded JSON response decoding.
func (c *Client) do(
	ctx context.Context,
	method, path string,
	payload any,
	target any,
) error {
	return c.doWithTimeout(ctx, method, path, payload, target, c.options.clientTimeout)
}

// doWithTimeout bounds each administrative request independently of the shared HTTP client.
func (c *Client) doWithTimeout(
	ctx context.Context,
	method, path string,
	payload any,
	target any,
	timeout time.Duration,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader

	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}

	destination := *c.url
	// Preserve the optional, URL-encoded inspection history page.
	pathPart, query, hasQuery := strings.Cut(path, "?")
	decodedPath, err := url.PathUnescape(pathPart)
	if err != nil {
		return fmt.Errorf("invalid administrative request path: %w", err)
	}
	destination.Path = c.url.Path + decodedPath
	destination.RawPath = c.url.EscapedPath() + pathPart
	if hasQuery {
		destination.RawQuery = query
	}

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
		var problem struct {
			// Error contains the safe error message returned by the API.
			Error string `json:"error"`
		}
		text := strings.TrimSpace(string(message))
		if json.Unmarshal(message, &problem) == nil && problem.Error != "" {
			text = problem.Error
		}
		if len(text) > 256 {
			text = text[:256]
		}
		return &Error{Code: res.StatusCode, Message: text}
	}

	// Read one byte beyond the limit so an oversized response is never accepted.
	data, err := io.ReadAll(io.LimitReader(res.Body, int64(c.options.maxAdminResponseBytes)+1))
	if err != nil {
		return fmt.Errorf("read application response: %w", err)
	}
	if len(data) > c.options.maxAdminResponseBytes {
		return fmt.Errorf("application response exceeds %d bytes", c.options.maxAdminResponseBytes)
	}

	// Unmarshal rejects trailing JSON documents and any non-whitespace suffix.
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode application response: %w", err)
	}

	return nil
}
