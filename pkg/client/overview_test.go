package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestOverviewClient(t *testing.T) {
	t.Parallel()

	t.Run("encodes revision filters and decodes a page", func(t *testing.T) {
		t.Parallel()
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/prefix/decisions/history", r.URL.Path)
			assert.Equal(t, "2", r.URL.Query().Get("page"))
			assert.Equal(t, "203.0.113.20", r.URL.Query().Get("ip"))
			assert.Equal(t, "unbanned", r.URL.Query().Get("state"))
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode(model.RevisionPage{Items: []model.Revision{{DecisionID: "one", Revision: 2, State: model.DecisionUnbanned}}, Page: 2})
		}))
		t.Cleanup(upstream.Close)
		api, err := client.New(upstream.URL+"/prefix", "secret")
		require.NoError(t, err)
		page, err := api.ListDecisionHistory(context.Background(), client.RevisionFilter{Page: 2, IP: "::ffff:203.0.113.20", State: model.DecisionUnbanned})
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		assert.Equal(t, "one", page.Items[0].DecisionID)
	})

	t.Run("encodes delivery filters", func(t *testing.T) {
		t.Parallel()
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/deliveries", r.URL.Path)
			assert.Equal(t, "exhausted", r.URL.Query().Get("status"))
			assert.Equal(t, "cloudflare.edge", r.URL.Query().Get("destination"))
			_ = json.NewEncoder(w).Encode(model.DeliveryOverviewPage{Items: []model.DeliveryOverview{{Destination: "cloudflare.edge", Status: model.DeliveryExhausted}}, Page: 1})
		}))
		t.Cleanup(upstream.Close)
		api, err := client.New(upstream.URL, "secret")
		require.NoError(t, err)
		page, err := api.ListDeliveries(context.Background(), client.DeliveryFilter{Page: 1, Status: model.DeliveryExhausted, Destination: "cloudflare.edge"})
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		assert.Equal(t, model.DeliveryExhausted, page.Items[0].Status)
	})

	t.Run("rejects invalid paging without an HTTP request", func(t *testing.T) {
		t.Parallel()
		api, err := client.New("http://127.0.0.1:1", "secret")
		require.NoError(t, err)
		_, err = api.ListDeliveries(context.Background(), client.DeliveryFilter{Page: -1})
		require.ErrorContains(t, err, "page must be positive")
	})
}

func TestListDeliveriesRejectsSuperseded(t *testing.T) {
	t.Parallel()

	t.Run("rejects historical statuses before contacting Warden", func(t *testing.T) {
		t.Parallel()
		api, err := client.New("http://127.0.0.1:8080", "admin-token")
		require.NoError(t, err)

		_, err = api.ListDeliveries(t.Context(), client.DeliveryFilter{Status: model.DeliverySuperseded})

		require.ErrorContains(t, err, "invalid status")
	})
}
