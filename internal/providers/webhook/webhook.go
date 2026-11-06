// Package webhook delivers signed desired-state notifications.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/signing"
)

// Provider posts decision updates to one configured endpoint.
type Provider struct {
	// URL is the destination endpoint.
	URL string
	// Secret signs each outbound request.
	Secret string
	// Client supplies bounded timeouts and disables redirects.
	Client *http.Client
}

// Apply signs the exact serialized decision and accepts only a successful response.
func (p Provider) Apply(ctx context.Context, d decisions.Decision) error {
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("construct webhook request")
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Warden-Timestamp", ts)
	req.Header.Set("X-Warden-Signature", signing.Signature(p.Secret, ts, body))

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
