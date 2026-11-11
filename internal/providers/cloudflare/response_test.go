package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		wantError string
	}{
		{
			name: "accepts one JSON document",
			body: `{"success":true,"result":[]}`,
		},
		{
			name: "accepts JSON whitespace",
			body: "{\"success\":true} \n\t",
		},
		{
			name:      "rejects trailing JSON document",
			body:      `{"success":true}{"success":true}`,
			wantError: "decode Cloudflare response",
		},
		{
			name:      "rejects invalid JSON",
			body:      `{"success":true`,
			wantError: "decode Cloudflare response",
		},
		{
			name:      "rejects oversized body even if the excess is whitespace",
			body:      `{"success":true}` + strings.Repeat(" ", maxResponseBytes),
			wantError: "Cloudflare response exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)
			provider := Provider{RulesURL: server.URL, Client: server.Client()}

			_, err := provider.call(t.Context(), http.MethodGet, server.URL, nil)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}
			assert.NoError(t, err)
		})
	}
}
