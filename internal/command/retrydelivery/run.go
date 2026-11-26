package retrydelivery

import (
	"context"

	"github.com/gi8lino/keycloak-warden/internal/command/output"
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Run sends a retry request to Warden and prints acknowledgement of queue admission.
func Run(ctx context.Context, applicationURL, token string, request client.RetryRequest, encode output.Encoder, opts ...client.Option) error {
	api, err := client.New(applicationURL, token, opts...)
	if err != nil {
		return err
	}
	if err := api.RetryDelivery(ctx, request); err != nil {
		return err
	}
	return encode(map[string]bool{"queued": true})
}
