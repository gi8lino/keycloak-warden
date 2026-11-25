package ban

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/internal/command/output"
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
		var buf bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			time.Hour,
			"incident response",
			output.New(yamlFormat(), &buf),
		)

		require.NoError(t, err)
		receivedMu.Lock()
		assert.Equal(t, []string{"203.0.113.10", "203.0.113.20"}, received)
		receivedMu.Unlock()

		var result output.Batch
		require.NoError(t, yaml.Load(buf.Bytes(), &result))
		assert.Equal(t, output.OperationBan, result.Operation)
		assert.Equal(t, 2, result.Succeeded)
		assert.Zero(t, result.Failed)
		require.Len(t, result.Results, 2)
		assert.Equal(t, "203.0.113.10", result.Results[0].IPAddress)
		assert.Equal(t, "203.0.113.20", result.Results[1].IPAddress)
		assert.True(t, result.Results[0].Success)
		assert.True(t, result.Results[1].Success)
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
		var buf bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20", "203.0.113.30"},
			time.Hour,
			"incident response",
			output.New(yamlFormat(), &buf),
		)

		require.ErrorContains(t, err, "failed 203.0.113.20")
		assert.True(t, strings.Contains(err.Error(), "rejected by test API"))
		receivedMu.Lock()
		assert.Equal(t, []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}, received)
		receivedMu.Unlock()

		var result output.Batch
		require.NoError(t, yaml.Load(buf.Bytes(), &result))
		assert.Equal(t, output.OperationBan, result.Operation)
		assert.Equal(t, 2, result.Succeeded)
		assert.Equal(t, 1, result.Failed)
		require.Len(t, result.Results, 3)
		assert.True(t, result.Results[0].Success)
		assert.False(t, result.Results[1].Success)
		assert.Contains(t, result.Results[1].Error, "rejected")
		assert.True(t, result.Results[2].Success)
	})
}

// yamlFormat provides an output format pointer for command tests.
func yamlFormat() *string {
	format := output.FormatYAML
	return &format
}

func TestRunFailures(t *testing.T) {
	t.Parallel()

	t.Run("invalid IP prevents API access and encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "admin", []string{"invalid-ip"}, time.Hour, "reason", func(any) error {
			encoded = true
			return nil
		})
		require.Error(t, err)
		assert.False(t, encoded)
	})

	t.Run("missing token fails before encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", []string{"203.0.113.10"}, time.Hour, "reason", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("encoding failure is returned after successful API call", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"decision":{"id":"one"}}`))
		}))
		defer server.Close()
		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, time.Hour, "reason", func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Succeeded)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
	})

	t.Run("joins request and encoding failures", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer server.Close()
		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, time.Hour, "reason", func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Failed)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
		assert.ErrorContains(t, err, "failed 203.0.113.10")
		assert.ErrorContains(t, err, "502")
	})

	t.Run("cancellation still reports a partial empty batch", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var batch output.Batch
		err := Run(ctx, "http://127.0.0.1:8080", "admin", []string{"203.0.113.10"}, time.Hour, "reason", func(value any) error {
			batch = value.(output.Batch)
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, output.OperationBan, batch.Operation)
		assert.Empty(t, batch.Results)
	})
}
