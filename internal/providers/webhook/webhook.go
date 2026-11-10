// Package webhook delivers HTTP notifications of desired security state.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Provider posts decision updates to one configured endpoint.
type Provider struct {
	// URL is the resolved destination endpoint.
	URL string
	// Headers contains resolved optional headers sent with every request.
	Headers http.Header
	// Client supplies bounded timeouts and disables redirects.
	Client *http.Client
}

// Apply posts the serialized decision and accepts only a successful response.
func (p Provider) Apply(ctx context.Context, d decisions.Decision) error {
	if !d.State.Valid() {
		return fmt.Errorf("invalid decision state %q", d.State)
	}

	body, err := json.Marshal(d)
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

// isSuccessfulStatus reports whether the HTTP status is in the 2xx range.
func isSuccessfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}
