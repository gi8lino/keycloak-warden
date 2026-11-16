package client_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("accepts loopback HTTP with a token", func(t *testing.T) {
		t.Parallel()

		client, err := client.New("http://127.0.0.1:8081", "secret")

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("rejects remote unencrypted HTTP", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("http://example.com:8081", "admin")

		require.Error(t, err)
	})

	t.Run("accepts remote HTTP with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		api, err := client.New(
			"http://keycloak-warden.keycloak.svc.cluster.local:8080/warden",
			"admin",
			client.WithAllowInsecureHTTP(),
		)

		require.NoError(t, err)
		assert.NotNil(t, api)
	})

	t.Run("accepts remote HTTPS with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		api, err := client.New("https://warden.example.com", "admin", client.WithAllowInsecureHTTP())

		require.NoError(t, err)
		assert.NotNil(t, api)
	})

	t.Run("rejects unsupported scheme with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("ftp://warden.example.com", "admin", client.WithAllowInsecureHTTP())

		require.ErrorContains(t, err, "HTTPS")
	})

	t.Run("rejects credentials with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("http://user:pass@warden.example.com", "admin", client.WithAllowInsecureHTTP())

		require.ErrorContains(t, err, "application-url")
	})

	t.Run("ignores nil option", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("http://warden:8080", "admin", nil)

		require.ErrorContains(t, err, "HTTPS")
	})

	t.Run("rejects URL credentials", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("http://user:pass@localhost:8081", "admin")

		require.Error(t, err)
	})

	t.Run("rejects unsupported schemes", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("ftp://localhost", "admin")

		require.Error(t, err)
	})

	t.Run("accepts application route prefix", func(t *testing.T) {
		t.Parallel()

		client, err := client.New("http://localhost:8081/warden", "admin")

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("rejects query parameters", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("https://localhost?debug=1", "admin")

		require.Error(t, err)
	})

	t.Run("requires admin token", func(t *testing.T) {
		t.Parallel()

		_, err := client.New("http://localhost:8081", "")

		require.ErrorContains(t, err, "admin-token")
	})
}

func TestValidateURL(t *testing.T) {
	t.Parallel()

	t.Run("accepts remote HTTPS", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, client.ValidateURL("https://warden.example.com:8443"))
	})

	t.Run("accepts local HTTP", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, client.ValidateURL("http://127.0.0.1:8081"))
	})

	t.Run("rejects remote HTTP", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("http://warden:8081"), "HTTPS")
	})

	t.Run("accepts remote HTTP with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, client.ValidateURL(
			"http://keycloak-warden.keycloak.svc.cluster.local:8080/warden",
			client.WithAllowInsecureHTTP(),
		))
	})

	t.Run("rejects unsupported scheme with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL(
			"ftp://keycloak-warden:8080",
			client.WithAllowInsecureHTTP(),
		), "HTTPS")
	})

	t.Run("rejects malformed URL with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL(
			"http://warden:8080?token=secret",
			client.WithAllowInsecureHTTP(),
		), "application-url")
	})

	t.Run("rejects invalid route prefix with explicit opt-in", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL(
			"http://warden:8080/warden//bans",
			client.WithAllowInsecureHTTP(),
		), "route prefix")
	})

	t.Run("ignores nil option", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("http://warden:8080", nil), "HTTPS")
	})

	t.Run("accepts prefixed application URL", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, client.ValidateURL("https://warden.example.com/warden"))
	})

	t.Run("rejects path traversal in route prefix", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("https://warden.example.com/warden/../bans"), "route prefix")
	})

	t.Run("rejects encoded route prefix", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("https://warden.example.com/ward%65n"), "application-url")
	})

	t.Run("rejects credentials", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("https://user:password@warden.example.com"), "application-url")
	})

	t.Run("rejects trailing question mark", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("https://warden.example.com?"), "application-url")
	})

	t.Run("rejects unsupported scheme", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("ftp://warden.example.com"), "HTTPS")
	})

	t.Run("rejects missing host", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, client.ValidateURL("https:///"), "application-url")
	})
}

func TestInsecureHTTPOptionRequests(t *testing.T) {
	t.Parallel()

	t.Run("preserves bearer authentication and URL prefix", func(t *testing.T) {
		t.Parallel()

		authHeader := make(chan string, 1)
		requestPath := make(chan string, 1)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader <- r.Header.Get("Authorization")
			requestPath <- r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[]"))
		}))
		t.Cleanup(server.Close)

		api, err := client.New(server.URL+"/warden", "secret", client.WithAllowInsecureHTTP())
		require.NoError(t, err)

		bans, err := api.List(t.Context())

		require.NoError(t, err)
		assert.Empty(t, bans)
		assert.Equal(t, "Bearer secret", <-authHeader)
		assert.Equal(t, "/warden/bans", <-requestPath)
	})

	t.Run("does not follow redirects", func(t *testing.T) {
		t.Parallel()

		redirected := make(chan struct{}, 1)
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			redirected <- struct{}{}
			_, _ = w.Write([]byte("[]"))
		}))
		t.Cleanup(destination.Close)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", destination.URL+"/bans")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}))
		t.Cleanup(server.Close)

		api, err := client.New(server.URL, "secret", client.WithAllowInsecureHTTP())
		require.NoError(t, err)

		_, err = api.List(t.Context())

		require.ErrorContains(t, err, "application HTTP 307")
		select {
		case <-redirected:
			t.Fatal("administrative client followed a redirect")
		default:
		}
	})
}
