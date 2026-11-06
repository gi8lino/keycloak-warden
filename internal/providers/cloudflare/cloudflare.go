// Package cloudflare reconciles Warden-owned zone IP Access rules.
package cloudflare

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

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Provider manages blocks in one Cloudflare zone.
type Provider struct {
	// RulesURL points to the zone's IP Access rules endpoint.
	RulesURL string
	// Token authorizes zone firewall changes.
	Token string
	// Client enforces a timeout and disables redirects.
	Client *http.Client
}

// filter identifies a single IPv4 or IPv6 address.
type filter struct {
	// Target selects Cloudflare's address family.
	Target string `json:"target"`
	// Value contains the normalized address.
	Value string `json:"value"`
}

// rule is the subset of the Cloudflare access rule used to verify ownership.
type rule struct {
	// ID is the remote identifier used for removal.
	ID string `json:"id,omitempty"`
	// Mode is block for Warden-managed rules.
	Mode string `json:"mode"`
	// Notes holds the unique Warden decision marker.
	Notes string `json:"notes"`
	// Configuration limits the rule to the desired address.
	Configuration filter `json:"configuration"`
}

// response contains Cloudflare's application status and operation-specific result.
type response struct {
	// Success distinguishes acknowledged operations from API errors.
	Success bool `json:"success"`
	// Result contains rules for a list operation.
	Result json.RawMessage `json:"result"`
	// Info describes the pagination of a list response.
	Info pagination `json:"result_info"`
}

// pagination tracks how many result pages the API returned.
type pagination struct {
	// Pages is the final page number.
	Pages int `json:"total_pages"`
}

// Apply discovers an owned rule before creation or release, including after an interrupted request.
func (p Provider) Apply(ctx context.Context, d decisions.Decision) error {
	addr, err := netip.ParseAddr(d.IP)
	if err != nil {
		return err
	}

	target := "ip"
	if addr.Is6() {
		target = "ip6"
	}

	want := rule{
		Mode:          "block",
		Notes:         "warden:" + d.ID,
		Configuration: filter{target, addr.String()},
	}

	owned, err := p.find(ctx, want)
	if err != nil {
		return err
	}

	if d.Active {
		if len(owned) > 0 {
			return nil
		}
		_, err = p.call(ctx, http.MethodPost, p.RulesURL, want)
		return err
	}

	for _, id := range owned {
		if _, err := p.call(ctx, http.MethodDelete, p.RulesURL+"/"+url.PathEscape(id), nil); err != nil {
			return err
		}
	}

	return nil
}

// find matches exact ownership, mode and address even when the API filters are broader.
func (p Provider) find(ctx context.Context, want rule) ([]string, error) {
	query := url.Values{
		"notes":               {want.Notes},
		"configuration.value": {want.Configuration.Value},
		"match":               {"all"},
	}

	var ids []string
	for page := 1; ; page++ {
		query.Set("page", fmt.Sprint(page))
		resp, err := p.call(ctx, http.MethodGet, p.RulesURL+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}

		var rules []rule
		if err := json.Unmarshal(resp.Result, &rules); err != nil {
			return nil, err
		}

		for _, r := range rules {
			if r.matches(want) {
				ids = append(ids, r.ID)
			}
		}

		if page >= resp.Info.Pages {
			return ids, nil
		}
	}
}

// matches checks all remote ownership and addressing fields before allowing deletion.
func (r rule) matches(want rule) bool {
	return r.ID != "" && r.Mode == want.Mode && r.Notes == want.Notes && r.Configuration == want.Configuration
}

// call sends a bounded API request without exposing credentials or remote error bodies to logs.
func (p Provider) call(ctx context.Context, method, endpoint string, body any) (response, error) {
	var out response
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return out, err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return out, errors.New("Cloudflare transport failed") //nolint:staticcheck
	}
	defer resp.Body.Close() // nolint:errcheck

	if !isSuccessfulStatus(resp.StatusCode) {
		return out, fmt.Errorf("Cloudflare HTTP %d", resp.StatusCode) //nolint:staticcheck
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return out, err
	}

	if !out.Success {
		return out, errors.New("Cloudflare rejected request") //nolint:staticcheck
	}
	return out, nil
}

// isSuccessfulStatus reports whether the HTTP status is in the 2xx range.
func isSuccessfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}
