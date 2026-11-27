package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gi8lino/keycloak-warden/pkg/model"
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
func (c *Client) Ban(ctx context.Context, request model.ManualBanRequest) (model.Record, error) {
	return c.doBanRequest(ctx, http.MethodPost, "/bans", createBanRequest{
		IPAddress: request.IP,
		Duration:  request.Duration.String(),
		Reason:    request.Reason,
	})
}

// Unban removes every active source for the specified decision ID.
func (c *Client) Unban(ctx context.Context, decisionID string) (model.Record, error) {
	if strings.TrimSpace(decisionID) == "" {
		return model.Record{}, errors.New("decision ID is required")
	}

	return c.doBanRequest(ctx, http.MethodDelete, "/bans/"+url.PathEscape(decisionID), nil)
}

// Get retrieves one persisted decision with its newest bounded history page.
func (c *Client) Get(ctx context.Context, decisionID string) (model.Record, error) {
	return c.GetPage(ctx, decisionID, 1)
}

// GetPage retrieves a one-based history page directly using SQLite LIMIT/OFFSET.
// The decision and acknowledgements always describe the latest persisted state.
func (c *Client) GetPage(ctx context.Context, decisionID string, page int) (model.Record, error) {
	return c.GetPageThroughRevision(ctx, decisionID, page, 0)
}

// GetPageThroughRevision excludes revisions newer than the first page of a traversal.
// A zero revision selects the latest history.
func (c *Client) GetPageThroughRevision(ctx context.Context, decisionID string, page int, throughRevision int64) (model.Record, error) {
	if strings.TrimSpace(decisionID) == "" {
		return model.Record{}, errors.New("decision ID is required")
	}

	if throughRevision < 0 {
		return model.Record{}, errors.New("history revision must be nonnegative")
	}

	if page < 1 {
		return model.Record{}, errors.New("history-page must be positive")
	}

	path := "/bans/" + url.PathEscape(decisionID)
	query := url.Values{}
	if page != 1 {
		query.Set("history-page", strconv.Itoa(page))
	}

	if throughRevision != 0 {
		query.Set("history-through-revision", strconv.FormatInt(throughRevision, 10))
	}

	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	return c.doBanRequest(ctx, http.MethodGet, path, nil)
}

// List fetches effective bans with their automatic and manual sources.
func (c *Client) List(ctx context.Context) ([]model.Record, error) {
	var list []model.Record
	if err := c.do(ctx, http.MethodGet, "/bans", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// doBanRequest executes an administrative ban request and decodes its record.
func (c *Client) doBanRequest(ctx context.Context, method, path string, payload any) (model.Record, error) {
	var result model.Record
	if err := c.do(ctx, method, path, payload, &result); err != nil {
		return model.Record{}, err
	}
	return result, nil
}
