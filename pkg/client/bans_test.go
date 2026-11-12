package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestClientBan(t *testing.T) {
	t.Parallel()

	t.Run("sends authenticated JSON to application API", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/bans", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))

			var request struct {
				// IP is the reported client address, which may be absent in an event.
				IP string `json:"ipAddress"`
				// Duration specifies how long the requested manual block should last.
				Duration string `json:"duration"`
				// Reason records the operator explanation for the requested block.
				Reason string `json:"reason"`
			}

			if err := json.NewDecoder(r.Body).Decode(&request); !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			assert.Equal(t, "203.0.113.22", request.IP)
			assert.Equal(t, "1h0m0s", request.Duration)
			assert.Equal(t, "incident", request.Reason)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"decision":{"id":"decision-id"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL, "admin-secret")
		require.NoError(t, err)

		view, err := api.Ban(t.Context(), client.ManualBanRequest{
			IP:       "203.0.113.22",
			Duration: time.Hour,
			Reason:   "incident",
		})

		require.NoError(t, err)
		assert.Equal(t, "decision-id", view.Decision.ID)
	})

	t.Run("sends requests beneath application route prefix", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/warden/bans", r.URL.Path)
			_, _ = w.Write([]byte(`{"decision":{"id":"prefixed"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL+"/warden/", "admin")
		require.NoError(t, err)

		view, err := api.Ban(t.Context(), client.ManualBanRequest{
			IP:       "203.0.113.22",
			Duration: time.Hour,
			Reason:   "incident",
		})

		require.NoError(t, err)
		assert.Equal(t, "prefixed", view.Decision.ID)
	})
}

func TestClientUnban(t *testing.T) {
	t.Parallel()

	t.Run("deletes only the requested decision ID", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/bans/decision-id", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"decision":{"id":"decision-id"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL, "admin-secret")
		require.NoError(t, err)

		record, err := api.Unban(t.Context(), "decision-id")

		require.NoError(t, err)
		assert.Equal(t, "decision-id", record.Decision.ID)
		assert.EqualValues(t, 1, calls.Load())
	})

	t.Run("rejects missing decision ID without network request", func(t *testing.T) {
		t.Parallel()

		api, err := client.New("http://localhost:8081", "admin")
		require.NoError(t, err)

		_, err = api.Unban(t.Context(), "  ")
		require.ErrorContains(t, err, "decision ID")
	})

	t.Run("deletes a decision beneath the application route prefix", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/warden/bans/stable", r.URL.Path)
			_, _ = w.Write([]byte(`{"decision":{"id":"stable"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL+"/warden", "admin")
		require.NoError(t, err)

		record, err := api.Unban(t.Context(), "stable")

		require.NoError(t, err)
		assert.EqualValues(t, 1, calls.Load())
		assert.Equal(t, "stable", record.Decision.ID)
	})
}

func TestClientGet(t *testing.T) {
	t.Parallel()

	t.Run("gets one decision with authorization and application prefix", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/warden/bans/decision-id", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"decision":{"id":"decision-id"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL+"/warden", "admin-secret")
		require.NoError(t, err)

		record, err := api.Get(t.Context(), "decision-id")
		require.NoError(t, err)
		assert.Equal(t, "decision-id", record.Decision.ID)
	})

	t.Run("does not send request for blank decision ID", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		api, err := client.New(server.URL, "admin-secret")
		require.NoError(t, err)

		_, err = api.Get(t.Context(), " ")
		require.ErrorContains(t, err, "decision ID")
		assert.Zero(t, calls.Load())
	})

	t.Run("propagates missing decision HTTP status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"missing"}`))
		}))
		defer server.Close()

		api, err := client.New(server.URL, "admin-secret")
		require.NoError(t, err)

		_, err = api.Get(t.Context(), "missing-id")
		require.ErrorContains(t, err, "404")
	})
}
