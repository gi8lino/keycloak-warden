package client

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// ListNotifications retrieves a page of retained notification deliveries.
func (c *Client) ListNotifications(ctx context.Context, beforeID int64) (model.NotificationPage, error) {
	var result model.NotificationPage

	if beforeID < 0 {
		return result, errors.New("invalid notification cursor")
	}

	path := "/notifications"
	if beforeID > 0 {
		path += "?before-id=" + strconv.FormatInt(beforeID, 10)
	}

	err := c.do(ctx, http.MethodGet, path, nil, &result)

	return result, err
}

// NotificationAttempts retrieves a page of completed notification sends.
func (c *Client) NotificationAttempts(ctx context.Context, id, beforeNumber int64) (model.NotificationAttemptPage, error) {
	var result model.NotificationAttemptPage

	if id < 1 || beforeNumber < 0 {
		return result, errors.New("invalid notification attempt selector")
	}

	path := "/notifications/" + strconv.FormatInt(id, 10) + "/attempts"

	if beforeNumber > 0 {
		path += "?before-number=" + strconv.FormatInt(beforeNumber, 10)
	}

	err := c.do(ctx, http.MethodGet, path, nil, &result)

	return result, err
}

// RetryNotification requeues one eligible exhausted notification delivery.
func (c *Client) RetryNotification(ctx context.Context, id int64, request model.NotificationRetryRequest) error {
	if id < 1 {
		return errors.New("invalid notification delivery ID")
	}

	var result model.RetryResponse
	return c.do(ctx, http.MethodPost, "/notifications/"+strconv.FormatInt(id, 10)+"/retry", request, &result)
}
