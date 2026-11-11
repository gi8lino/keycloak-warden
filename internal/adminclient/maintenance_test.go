package adminclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaintenance(t *testing.T) {
	t.Parallel()

	t.Run("route prefix and bearer authentication apply to status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/warden/maintenance", r.URL.Path)
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"prune":{},"optimize":{},"pruneInterval":"1h0m0s","optimizeInterval":"24h0m0s"}`))
		}))
		defer server.Close()

		client, err := New(server.URL+"/warden", "secret")
		require.NoError(t, err)

		status, err := client.MaintenanceStatus(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "1h0m0s", status.PruneInterval)
	})

	t.Run("invalid JSON fails closed", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer server.Close()

		client, err := New(server.URL, "secret")
		require.NoError(t, err)

		_, err = client.PruneObservations(t.Context())
		require.ErrorContains(t, err, "decode application response")
	})

	t.Run("unauthorized write is rejected", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/maintenance/optimize", r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		client, err := New(server.URL, "wrong-secret")
		require.NoError(t, err)

		_, err = client.OptimizeDatabase(t.Context())
		require.ErrorContains(t, err, "401")
	})
}

// maintenanceTransport inspects the client-side request context without a network round trip.
type maintenanceTransport func(*http.Request) (*http.Response, error)

func (f maintenanceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// maintenanceTimeoutClient checks the request method, path, and maintenance deadline.
func maintenanceTimeoutClient(t *testing.T, method, path string) *Client {
	t.Helper()

	client, err := New("http://127.0.0.1:8081", "secret")
	require.NoError(t, err)

	client.http.Transport = maintenanceTransport(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, method, r.Method)
		assert.Equal(t, path, r.URL.Path)

		deadline, ok := r.Context().Deadline()
		require.True(t, ok, "all maintenance requests must have a deadline")

		remaining := time.Until(deadline)
		assert.Greater(t, remaining, 30*time.Second)
		assert.LessOrEqual(t, remaining, maintenanceClientTimeout)

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"prune":{},"optimize":{}}`)),
		}, nil
	})

	return client
}

func TestMaintenanceTimeout(t *testing.T) {
	t.Parallel()

	t.Run("status uses maintenance timeout", func(t *testing.T) {
		t.Parallel()

		client := maintenanceTimeoutClient(t, http.MethodGet, "/maintenance")

		_, err := client.MaintenanceStatus(t.Context())
		require.NoError(t, err)
	})

	t.Run("prune uses maintenance timeout", func(t *testing.T) {
		t.Parallel()

		client := maintenanceTimeoutClient(t, http.MethodPost, "/maintenance/prune")

		_, err := client.PruneObservations(t.Context())
		require.NoError(t, err)
	})

	t.Run("optimize uses maintenance timeout", func(t *testing.T) {
		t.Parallel()

		client := maintenanceTimeoutClient(t, http.MethodPost, "/maintenance/optimize")

		_, err := client.OptimizeDatabase(t.Context())
		require.NoError(t, err)
	})
}
