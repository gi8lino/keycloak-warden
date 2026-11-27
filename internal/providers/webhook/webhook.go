// Package webhook delivers typed payloads over HTTP.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/containeroo/notifykit/response"
	"github.com/containeroo/notifykit/templates"
)

const (
	// maxBodyBytes limits a rendered JSON webhook notification to 64 KiB.
	maxBodyBytes = 64 << 10
	// maxResponseBytes limits untrusted webhook response bodies inspected by a rule.
	maxResponseBytes = 64 << 10
)

// Provider posts typed JSON payloads to one configured endpoint.
type Provider[T any] struct {
	// URL is the resolved destination endpoint.
	URL string
	// Headers contains resolved optional headers sent with every request.
	Headers http.Header
	// Client supplies bounded timeouts and disables redirects.
	Client *http.Client
	// Template optionally renders custom JSON from the payload.
	// A nil template preserves the canonical JSON payload.
	Template *templates.Template
	// TemplateVars contains the resolved variables for this destination.
	TemplateVars map[string]string
	// Response optionally checks the HTTP status and body with Notifykit rules.
	// When nil, only HTTP 2xx is accepted and the body is not inspected.
	Response *response.Rule
}

// Deliver serializes or renders the payload and sends it to the configured endpoint.
func (p Provider[T]) Deliver(ctx context.Context, payload T) error {
	body, err := p.renderBody(payload)
	if err != nil {
		return err
	}

	return p.postJSON(ctx, body)
}

// postJSON sends a bounded JSON payload and evaluates the configured response.
func (p Provider[T]) postJSON(ctx context.Context, body []byte) error {
	if len(body) > maxBodyBytes || !json.Valid(body) {
		return errors.New("invalid or oversized webhook JSON body")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("construct webhook request")
	}

	req.Header = p.Headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return webhookTransportError(err)
	}
	defer resp.Body.Close() // nolint:errcheck

	if p.Response == nil {
		if !isSuccessfulStatus(resp.StatusCode) {
			return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
		}
		return nil
	}

	if !p.Response.HasBodyMatcher() {
		return p.Response.Evaluate(resp.StatusCode, nil)
	}

	// Read only what the matcher can safely inspect; never include the raw body
	// in errors when it exceeds the configured bound.
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("webhook HTTP %d: cannot read response body", resp.StatusCode)
	}
	if len(responseBody) > maxResponseBytes {
		return fmt.Errorf("webhook HTTP %d: response body exceeds 64 KiB limit", resp.StatusCode)
	}

	return p.Response.Evaluate(resp.StatusCode, responseBody)
}

// ValidateTemplate renders representative payloads supplied by the caller before startup.
func (p Provider[T]) ValidateTemplate(samples ...T) error {
	if p.Template == nil {
		return nil
	}

	for i, sample := range samples {
		if _, err := p.renderBody(sample); err != nil {
			return fmt.Errorf("payload %d: %w", i+1, err)
		}
	}
	return nil
}

// templateData exposes the payload and destination-specific variables.
type templateData[T any] struct {
	// Payload contains the value being delivered.
	Payload T
	// Vars contains explicitly configured template variables.
	Vars map[string]string
}

// renderBody serializes the payload or renders the configured JSON template.
func (p Provider[T]) renderBody(payload T) ([]byte, error) {
	if p.Template == nil {
		return json.Marshal(payload)
	}

	body, err := p.Template.Render(templateData[T]{
		Payload: payload,
		Vars:    p.TemplateVars,
	})
	if err != nil {
		return nil, fmt.Errorf("render webhook body: %w", err)
	}
	if len(body) > maxBodyBytes {
		return nil, errors.New("render webhook body: exceeds 64 KiB limit")
	}
	if !json.Valid(body) {
		return nil, errors.New("render webhook body: invalid JSON")
	}
	return body, nil
}

// isSuccessfulStatus reports whether the HTTP status is in the 2xx range.
func isSuccessfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}
