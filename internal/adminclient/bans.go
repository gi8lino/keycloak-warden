package adminclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

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
func (c *Client) Ban(ctx context.Context, request bans.ManualBanRequest) (bans.Record, error) {
	return c.doBanRequest(ctx, http.MethodPost, "/bans", createBanRequest{
		IPAddress: request.IP,
		Duration:  request.Duration.String(),
		Reason:    request.Reason,
	})
}

// Unban removes every active source for the specified decision ID.
func (c *Client) Unban(ctx context.Context, decisionID string) (bans.Record, error) {
	if strings.TrimSpace(decisionID) == "" {
		return bans.Record{}, errors.New("decision ID is required")
	}

	return c.doBanRequest(ctx, http.MethodDelete, "/bans/"+url.PathEscape(decisionID), nil)
}

// Get retrieves one persisted decision, including released records and delivery acknowledgements.
func (c *Client) Get(ctx context.Context, decisionID string) (bans.Record, error) {
	if strings.TrimSpace(decisionID) == "" {
		return bans.Record{}, errors.New("decision ID is required")
	}
	return c.doBanRequest(ctx, http.MethodGet, "/bans/"+url.PathEscape(decisionID), nil)
}

// List fetches effective bans with their automatic and manual sources.
func (c *Client) List(ctx context.Context) ([]bans.Record, error) {
	var list []bans.Record
	if err := c.do(ctx, http.MethodGet, "/bans", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// doBanRequest executes an administrative ban request and decodes its record.
func (c *Client) doBanRequest(ctx context.Context, method, path string, payload any) (bans.Record, error) {
	var result bans.Record
	if err := c.do(ctx, method, path, payload, &result); err != nil {
		return bans.Record{}, err
	}
	return result, nil
}
