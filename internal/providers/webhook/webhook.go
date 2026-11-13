// Package webhook delivers HTTP notifications of desired security state.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/containeroo/notifykit/templates"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// maxBodyBytes limits a rendered JSON webhook notification to 64 KiB.
const maxBodyBytes = 64 << 10

// Provider posts decision updates to one configured endpoint.
type Provider struct {
	// URL is the resolved destination endpoint.
	URL string
	// Headers contains resolved optional headers sent with every request.
	Headers http.Header
	// Client supplies bounded timeouts and disables redirects.
	Client *http.Client
	// Template optionally renders custom JSON from the decision fields.
	// A nil template preserves the original decision JSON payload.
	Template *templates.Template
}

// Apply posts the serialized decision and accepts only a successful response.
func (p Provider) Apply(ctx context.Context, d decisions.Decision) error {
	if !d.State.Valid() {
		return fmt.Errorf("invalid decision state %q", d.State)
	}

	body, err := p.renderBody(d)
	if err != nil {
		return err
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
		return fmt.Errorf("webhook transport failed")
	}
	defer resp.Body.Close() // nolint:errcheck

	if !isSuccessfulStatus(resp.StatusCode) {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// ValidateTemplate validates both ban and unban payloads before serving requests.
// Custom templates are compiled and checked once during provider initialization.
func (p Provider) ValidateTemplate() error {
	if p.Template == nil {
		return nil
	}

	decision := decisions.Decision{
		ID:        "startup-check",
		Revision:  1,
		IP:        "203.0.113.1",
		State:     decisions.StateBanned,
		ExpiresAt: time.Unix(0, 0).UTC(),
	}
	if _, err := p.renderBody(decision); err != nil {
		return fmt.Errorf("banned state: %w", err)
	}

	decision.State = decisions.StateUnbanned
	if _, err := p.renderBody(decision); err != nil {
		return fmt.Errorf("unbanned state: %w", err)
	}

	return nil
}

// renderBody either preserves the canonical decision JSON or renders the configured template.
func (p Provider) renderBody(decision decisions.Decision) ([]byte, error) {
	if p.Template == nil {
		return json.Marshal(decision)
	}

	body, err := p.Template.Render(decision)
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
