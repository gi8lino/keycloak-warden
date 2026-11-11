package adminclient_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
)

// responseClient creates a client backed by one scripted HTTP response.
func responseClient(t *testing.T, status int, body string) *adminclient.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client, err := adminclient.New(server.URL, "test-token")
	require.NoError(t, err)
	return client
}

func TestAdminResponseValidation(t *testing.T) {
	t.Parallel()

	t.Run("accepts one JSON response", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, `[{"decision":{"id":"one"},"sources":[],"deliveries":[]}]`)
		list, err := client.List(t.Context())
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "one", list[0].Decision.ID)
	})

	t.Run("accepts trailing JSON whitespace", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, "[] \n\t")
		list, err := client.List(t.Context())
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("rejects second JSON document", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, "[] []")
		_, err := client.List(t.Context())
		require.ErrorContains(t, err, "decode application response")
	})

	t.Run("rejects junk after JSON document", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, "[]garbage")
		_, err := client.List(t.Context())
		require.ErrorContains(t, err, "decode application response")
	})

	t.Run("rejects oversized response even if extra bytes are whitespace", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, "[]"+strings.Repeat(" ", 1<<20))
		_, err := client.List(t.Context())
		require.ErrorContains(t, err, "application response exceeds")
	})

	t.Run("accepts response exactly at byte limit", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, "[]"+strings.Repeat(" ", (1<<20)-2))
		list, err := client.List(t.Context())
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("rejects empty success response", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusOK, "")
		_, err := client.List(t.Context())
		require.ErrorContains(t, err, "decode application response")
	})

	t.Run("preserves unsuccessful HTTP status", func(t *testing.T) {
		t.Parallel()
		client := responseClient(t, http.StatusForbidden, `{"error":"forbidden"}`)
		_, err := client.List(t.Context())
		require.ErrorContains(t, err, "application HTTP 403")
	})
}
