// Package webhook delivers typed payloads over HTTP.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/containeroo/notifykit/notify"
	"github.com/containeroo/notifykit/response"
	notifywebhook "github.com/containeroo/notifykit/targets/webhook"
	"github.com/containeroo/notifykit/templates"
)

const (
	// maxBodyBytes limits serialized or rendered webhook JSON to 64 KiB.
	maxBodyBytes = 64 << 10
	// maxResponseBytes limits untrusted response bodies inspected by a rule.
	maxResponseBytes = 64 << 10
)

// NewTarget configures Notifykit with Warden's JSON delivery limits and response policy.
// The supplied HTTP client owns timeout and redirect policy.
func NewTarget(endpoint string, headers map[string]string, client *http.Client, rule *response.Rule) *notifywebhook.Target {
	opts := []notifywebhook.Option{
		notifywebhook.WithURL(endpoint),
		notifywebhook.WithHeaders(headers),
		notifywebhook.WithHeader("Content-Type", "application/json"),
		notifywebhook.WithClient(client),
		notifywebhook.WithValidateJSON(),
		notifywebhook.WithRequestBodyLimit(maxBodyBytes),
		notifywebhook.WithResponseBodyLimit(maxResponseBytes),
		notifywebhook.WithDiscardResponseBody(),
	}
	if rule != nil {
		opts = append(opts, notifywebhook.WithResponseRule(*rule))
	}
	return notifywebhook.New(opts...)
}

// Provider renders typed JSON payloads and delegates HTTP delivery to Notifykit.
type Provider[T any] struct {
	// Target sends the serialized or rendered JSON body without managed retries.
	Target *notifywebhook.Target
	// Template optionally renders custom JSON from the payload.
	// A nil template preserves the canonical JSON payload.
	Template *templates.Template
	// TemplateVars contains the resolved variables for this destination.
	TemplateVars map[string]string
}

// Deliver serializes or renders the payload and sends it once.
func (p Provider[T]) Deliver(ctx context.Context, payload T) error {
	body, err := p.renderBody(payload)
	if err != nil {
		return err
	}

	result, err := p.Target.SendBody(ctx, body)
	if notify.IsTransport(err) {
		if result.StatusCode != 0 {
			return fmt.Errorf("webhook HTTP %d: cannot read response body", result.StatusCode)
		}
		return webhookTransportError(err)
	}
	return err
}

// ValidatePayloads validates representative payloads and request settings before startup.
func (p Provider[T]) ValidatePayloads(samples ...T) error {
	for i, sample := range samples {
		body, err := p.renderBody(sample)
		if err != nil {
			return fmt.Errorf("payload %d: %w", i+1, err)
		}
		if err := p.Target.ValidateBody(body); err != nil {
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
	return body, nil
}
