package adminclient_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/command/adminclient"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("accepts loopback HTTP with a token", func(t *testing.T) {
		t.Parallel()

		client, err := adminclient.New("http://127.0.0.1:8081", "secret")

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("rejects remote unencrypted HTTP", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("http://example.com:8081", "admin")

		require.Error(t, err)
	})

	t.Run("rejects URL credentials", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("http://user:pass@localhost:8081", "admin")

		require.Error(t, err)
	})

	t.Run("rejects unsupported schemes", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("ftp://localhost", "admin")

		require.Error(t, err)
	})

	t.Run("accepts application route prefix", func(t *testing.T) {
		t.Parallel()

		client, err := adminclient.New("http://localhost:8081/warden", "admin")

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("rejects query parameters", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("https://localhost?debug=1", "admin")

		require.Error(t, err)
	})

	t.Run("requires admin token", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("http://localhost:8081", "")

		require.ErrorContains(t, err, "admin-token")
	})
}

func TestValidateURL(t *testing.T) {
	t.Parallel()

	t.Run("accepts remote HTTPS", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, adminclient.ValidateURL("https://warden.example.com:8443"))
	})

	t.Run("accepts local HTTP", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, adminclient.ValidateURL("http://127.0.0.1:8081"))
	})

	t.Run("rejects remote HTTP", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("http://warden:8081"), "HTTPS")
	})

	t.Run("accepts prefixed application URL", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, adminclient.ValidateURL("https://warden.example.com/warden"))
	})

	t.Run("rejects path traversal in route prefix", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://warden.example.com/warden/../bans"), "route prefix")
	})

	t.Run("rejects encoded route prefix", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://warden.example.com/ward%65n"), "application-url")
	})

	t.Run("rejects credentials", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://user:password@warden.example.com"), "application-url")
	})

	t.Run("rejects trailing question mark", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://warden.example.com?"), "application-url")
	})

	t.Run("rejects unsupported scheme", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("ftp://warden.example.com"), "HTTPS")
	})

	t.Run("rejects missing host", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https:///"), "application-url")
	})
}

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
		client, err := adminclient.New(server.URL, "admin-secret")

		require.NoError(t, err)
		view, err := client.Ban(t.Context(), bans.Request{IP: "203.0.113.22", Duration: time.Hour, Reason: "incident"})

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

		client, err := adminclient.New(server.URL+"/warden/", "admin")
		require.NoError(t, err)

		view, err := client.Ban(t.Context(), bans.Request{
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

	t.Run("unbans by decision ID", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/bans/decision-id", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"decision":{"id":"decision-id"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()
		client, err := adminclient.New(server.URL, "admin-secret")

		require.NoError(t, err)
		view, err := client.Unban(t.Context(), "decision-id")

		require.NoError(t, err)
		assert.Equal(t, "decision-id", view.Decision.ID)
	})

	t.Run("resolves IP to stable decision ID", func(t *testing.T) {
		t.Parallel()

		var getCalled atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			switch r.Method {
			case http.MethodGet:
				getCalled.Store(true)
				_, _ = w.Write([]byte(`[{"decision":{"id":"stable-id","ipAddress":"203.0.113.22","active":true},"sources":[{"kind":"manual"}],"deliveries":[]}]`))
			case http.MethodDelete:
				assert.Equal(t, "/bans/stable-id", r.URL.Path)
				_, _ = w.Write([]byte(`{"decision":{"id":"stable-id","active":false},"sources":[],"deliveries":[]}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()
		client, err := adminclient.New(server.URL, "admin-secret")

		require.NoError(t, err)
		view, err := client.Unban(t.Context(), "::ffff:203.0.113.22")

		require.NoError(t, err)
		assert.True(t, getCalled.Load())
		assert.Equal(t, "stable-id", view.Decision.ID)
	})

	t.Run("rejects empty identifier", func(t *testing.T) {
		t.Parallel()

		client, err := adminclient.New("http://localhost:8081", "admin")

		require.NoError(t, err)
		_, err = client.Unban(t.Context(), "  ")

		require.ErrorContains(t, err, "decision ID")
	})

	t.Run("resolves and deletes IP under route prefix", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				assert.Equal(t, "/warden/bans", r.URL.Path)
				_, _ = w.Write([]byte(`[{"decision":{"id":"stable","ipAddress":"203.0.113.22"}}]`))
			case http.MethodDelete:
				assert.Equal(t, "/warden/bans/stable", r.URL.Path)
				_, _ = w.Write([]byte(`{"decision":{"id":"stable"}}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		client, err := adminclient.New(server.URL+"/warden", "admin")
		require.NoError(t, err)

		view, err := client.Unban(t.Context(), "203.0.113.22")
		require.NoError(t, err)
		assert.Equal(t, "stable", view.Decision.ID)
	})
}
