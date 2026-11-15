package client_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/pkg/client"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

func TestPublicResponseTypes(t *testing.T) {
	t.Parallel()

	t.Run("decisions and acknowledgements retain the wire fields", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[{"decision":{"id":"one","revision":4,"ipAddress":"203.0.113.1","state":"banned"},"sources":[{"kind":"manual","reason":"test"}],"deliveries":[{"destination":"webhook.edge","acknowledgedRevision":3}]}]`))
		}))
		defer server.Close()

		api, err := client.New(server.URL, "secret")
		require.NoError(t, err)

		records, err := api.List(t.Context())
		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Equal(t, "203.0.113.1", records[0].Decision.IP)
		assert.Equal(t, decisionstate.StateBanned, records[0].Decision.State)
		assert.Equal(t, "manual", records[0].Sources[0].Kind)
		assert.Equal(t, int64(3), records[0].Deliveries[0].Revision)
	})

	t.Run("maintenance retains task timestamps", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"prune":{"lastSuccessAt":"2026-11-12T12:00:00Z"},"optimize":{},"pruneInterval":"1h0m0s"}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL, "secret")
		require.NoError(t, err)

		status, err := api.MaintenanceStatus(t.Context())
		require.NoError(t, err)
		require.NotNil(t, status.Prune.LastSuccessAt)
		assert.Equal(t, time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC), *status.Prune.LastSuccessAt)
	})
}

func TestTypedHTTPError(t *testing.T) {
	t.Parallel()

	t.Run("preserves status without revealing bearer token", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"decision not found"}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL, "private-secret")
		require.NoError(t, err)

		_, err = api.Get(t.Context(), "unknown")
		require.Error(t, err)
		var problem *client.Error
		require.True(t, errors.As(err, &problem))
		assert.Equal(t, http.StatusNotFound, problem.Code)
		assert.Contains(t, problem.Error(), "decision not found")
		assert.NotContains(t, problem.Error(), "private-secret")
	})
}

// TestDecisionStateSerialization verifies that the shared enum retains the wire format.
func TestDecisionStateSerialization(t *testing.T) {
	t.Parallel()

	t.Run("banned JSON", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(client.Decision{State: decisionstate.StateBanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"state":"banned"`)

		var decoded client.Decision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, decisionstate.StateBanned, decoded.State)
	})

	t.Run("unbanned JSON", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(client.Decision{State: decisionstate.StateUnbanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"state":"unbanned"`)

		var decoded client.Decision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, decisionstate.StateUnbanned, decoded.State)
	})

	t.Run("banned YAML", func(t *testing.T) {
		t.Parallel()

		encoded, err := yaml.Marshal(client.Decision{State: decisionstate.StateBanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "state: banned")

		var decoded client.Decision
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, decisionstate.StateBanned, decoded.State)
	})

	t.Run("unbanned YAML", func(t *testing.T) {
		t.Parallel()

		encoded, err := yaml.Marshal(client.Decision{State: decisionstate.StateUnbanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "state: unbanned")

		var decoded client.Decision
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, decisionstate.StateUnbanned, decoded.State)
	})
}

// TestDeliveryDesiredStateSerialization verifies that delivery history shares the same enum.
func TestDeliveryDesiredStateSerialization(t *testing.T) {
	t.Parallel()

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(client.Delivery{DesiredState: decisionstate.StateBanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"desiredState":"banned"`)

		var decoded client.Delivery
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, decisionstate.StateBanned, decoded.DesiredState)
	})

	t.Run("YAML", func(t *testing.T) {
		t.Parallel()

		encoded, err := yaml.Marshal(client.Delivery{DesiredState: decisionstate.StateUnbanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "desiredState: unbanned")

		var decoded client.Delivery
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, decisionstate.StateUnbanned, decoded.DesiredState)
	})
}
