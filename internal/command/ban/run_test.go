package ban

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clioutput "github.com/gi8lino/keycloak-warden/internal/output"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("bans each requested IP using the same duration and reason", func(t *testing.T) {
		t.Parallel()

		var received []string
		var receivedMu sync.Mutex
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
			receivedMu.Lock()
			received = append(received, request.IP)
			receivedMu.Unlock()

			assert.Equal(t, "1h0m0s", request.Duration)
			assert.Equal(t, "incident response", request.Reason)
			_, _ = w.Write([]byte(`{"decision":{"id":"stable-id"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()
		var output bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			time.Hour,
			"incident response",
			clioutput.New(textFormat(), &output),
		)

		require.NoError(t, err)
		receivedMu.Lock()
		assert.Equal(t, []string{"203.0.113.10", "203.0.113.20"}, received)
		receivedMu.Unlock()

		assert.Equal(t, "Banned 203.0.113.10\nBanned 203.0.113.20\n2 succeeded, 0 failed\n", output.String())
	})

	t.Run("continues after a rejected IP and aggregates errors", func(t *testing.T) {
		t.Parallel()

		var received []string
		var receivedMu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				// IP is the reported client address, which may be absent in an event.
				IP string `json:"ipAddress"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			receivedMu.Lock()
			received = append(received, request.IP)
			receivedMu.Unlock()
			if request.IP == "203.0.113.20" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("rejected by test API"))
				return
			}
			_, _ = w.Write([]byte(`{"decision":{"id":"stable-id"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()
		var output bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20", "203.0.113.30"},
			time.Hour,
			"incident response",
			clioutput.New(textFormat(), &output),
		)

		require.ErrorContains(t, err, "failed 203.0.113.20")
		assert.True(t, strings.Contains(err.Error(), "rejected by test API"))
		receivedMu.Lock()
		assert.Equal(t, []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}, received)
		receivedMu.Unlock()

		assert.Equal(t, "Banned 203.0.113.10\nBanned 203.0.113.30\n2 succeeded, 1 failed\n", output.String())
	})
}

// textFormat provides an output format pointer for command tests.
func textFormat() *string {
	format := clioutput.FormatText
	return &format
}
