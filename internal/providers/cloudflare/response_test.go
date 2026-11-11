package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// callResponse sends a request to a mock Cloudflare API returning the given response body.
func callResponse(t *testing.T, body string) error {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	provider := Provider{
		RulesURL: server.URL,
		Client:   server.Client(),
	}
	_, err := provider.call(t.Context(), http.MethodGet, server.URL, nil)
	return err
}

func TestResponseValidation(t *testing.T) {
	t.Parallel()

	t.Run("accepts one JSON document", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, `{"success":true,"result":[]}`)
		require.NoError(t, err)
	})

	t.Run("accepts JSON whitespace", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, "{\"success\":true} \n\t")
		require.NoError(t, err)
	})

	t.Run("rejects trailing JSON document", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, `{"success":true}{"success":true}`)
		require.ErrorContains(t, err, "decode Cloudflare response")
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		t.Parallel()

		err := callResponse(t, `{"success":true`)
		require.ErrorContains(t, err, "decode Cloudflare response")
	})

	t.Run("rejects oversized body even if the excess is whitespace", func(t *testing.T) {
		t.Parallel()

		body := `{"success":true}` + strings.Repeat(" ", maxResponseBytes)
		err := callResponse(t, body)
		require.ErrorContains(t, err, "Cloudflare response exceeds")
	})
}
