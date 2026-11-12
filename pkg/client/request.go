package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// maxAdminResponseBytes limits successful administrative API response bodies to one MiB.
	maxAdminResponseBytes = 1 << 20
	// clientTimeout bounds the total duration of an ordinary administrative HTTP request.
	clientTimeout = 10 * time.Second
	// maintenanceClientTimeout exceeds the server's 30-second maintenance deadline.
	maintenanceClientTimeout = 35 * time.Second
)

// do performs an authenticated administrative request with bounded JSON response decoding.
func (c *Client) do(
	ctx context.Context,
	method, path string,
	payload any,
	target any,
) error {
	return c.doWithTimeout(ctx, method, path, payload, target, clientTimeout)
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
		var problem struct {
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
