package unban

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/internal/command/output"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("unbans each IP through its stable decision ID", func(t *testing.T) {
		t.Parallel()

		var deleted []string
		var deletedMu sync.Mutex
		var gets atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			switch r.Method {
			case http.MethodGet:
				gets.Add(1)

				assert.Equal(t, "/bans", r.URL.Path)
				_, _ = w.Write([]byte(`[{"decision":{"id":"id-10","ipAddress":"203.0.113.10","state":"banned"},"sources":[{"kind":"automatic"}],"deliveries":[]},{"decision":{"id":"id-20","ipAddress":"203.0.113.20","state":"banned"},"sources":[{"kind":"manual"}],"deliveries":[]}]`))
			case http.MethodDelete:
				deletedMu.Lock()
				deleted = append(deleted, r.URL.Path)
				deletedMu.Unlock()
				_, _ = w.Write([]byte(`{"decision":{"state":"unbanned"},"sources":[],"deliveries":[]}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()
		var buf bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			output.New(yamlFormat(), &buf),
		)

		require.NoError(t, err)
		deletedMu.Lock()
		assert.Equal(t, []string{"/bans/id-10", "/bans/id-20"}, deleted)
		deletedMu.Unlock()

		assert.EqualValues(t, 1, gets.Load())
		var result output.Batch
		require.NoError(t, yaml.Load(buf.Bytes(), &result))
		assert.Equal(t, output.OperationUnban, result.Operation)
		assert.Equal(t, 2, result.Succeeded)
		assert.Zero(t, result.Failed)
		require.Len(t, result.Results, 2)
		assert.True(t, result.Results[0].Success)
		assert.True(t, result.Results[1].Success)
	})

	t.Run("reports failed unban while continuing to the next IP", func(t *testing.T) {
		t.Parallel()

		var deleted []string
		var deletedMu sync.Mutex
		var gets atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				gets.Add(1)
				_, _ = w.Write([]byte(`[{"decision":{"id":"id-10","ipAddress":"203.0.113.10"}},{"decision":{"id":"id-20","ipAddress":"203.0.113.20"}}]`))
			case http.MethodDelete:
				deletedMu.Lock()
				deleted = append(deleted, r.URL.Path)
				deletedMu.Unlock()
				if r.URL.Path == "/bans/id-10" {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte("provider unavailable"))
					return
				}
				_, _ = w.Write([]byte(`{"decision":{"state":"unbanned"},"sources":[],"deliveries":[]}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()
		var buf bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			output.New(yamlFormat(), &buf),
		)

		require.ErrorContains(t, err, "failed 203.0.113.10")
		assert.ErrorContains(t, err, "provider unavailable")
		deletedMu.Lock()
		assert.Equal(t, []string{"/bans/id-10", "/bans/id-20"}, deleted)
		deletedMu.Unlock()

		assert.EqualValues(t, 1, gets.Load())
		var result output.Batch
		require.NoError(t, yaml.Load(buf.Bytes(), &result))
		assert.Equal(t, output.OperationUnban, result.Operation)
		assert.Equal(t, 1, result.Succeeded)
		assert.Equal(t, 1, result.Failed)
		require.Len(t, result.Results, 2)
		assert.False(t, result.Results[0].Success)
		assert.True(t, result.Results[1].Success)
	})

	t.Run("reports an unbanned IP as not found and continues", func(t *testing.T) {
		t.Parallel()

		var deletes atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`[{"decision":{"id":"id-20","ipAddress":"203.0.113.20"}}]`))
			case http.MethodDelete:
				deletes.Add(1)
				_, _ = w.Write([]byte(`{"decision":{"state":"unbanned"},"sources":[],"deliveries":[]}`))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()
		var buf bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			output.New(yamlFormat(), &buf),
		)

		require.ErrorContains(t, err, "failed 203.0.113.10: active ban not found")
		assert.EqualValues(t, 1, deletes.Load())
		var result output.Batch
		require.NoError(t, yaml.Load(buf.Bytes(), &result))
		assert.Equal(t, output.OperationUnban, result.Operation)
		assert.Equal(t, 1, result.Succeeded)
		assert.Equal(t, 1, result.Failed)
		require.Len(t, result.Results, 2)
		assert.False(t, result.Results[0].Success)
		assert.True(t, result.Results[1].Success)
	})
}

// yamlFormat provides an output format pointer for command tests.
func yamlFormat() *string {
	format := output.FormatYAML
	return &format
}

func TestRunFailures(t *testing.T) {
	t.Parallel()

	t.Run("invalid IP fails before connecting", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "admin", []string{"bad-ip"}, func(any) error {
			encoded = true
			return nil
		})
		require.Error(t, err)
		assert.False(t, encoded)
	})

	t.Run("missing token fails before connecting", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", []string{"203.0.113.10"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("list failure does not encode results", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		encoded := false
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "list active bans")
		assert.ErrorContains(t, err, "503")
		assert.False(t, encoded)
	})

	t.Run("encoding failure propagates after successful release", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`[{"decision":{"id":"one","ipAddress":"203.0.113.10"}}]`))
				return
			}
			_, _ = w.Write([]byte(`{"decision":{"id":"one","state":"unbanned"}}`))
		}))
		defer server.Close()
		encodeErr := errors.New("cannot write output")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Succeeded)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
	})

	t.Run("joins missing decision and encoding failures", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		}))
		defer server.Close()
		encodeErr := errors.New("cannot write output")
		err := Run(t.Context(), server.URL, "admin", []string{"203.0.113.10"}, func(value any) error {
			batch, ok := value.(output.Batch)
			require.True(t, ok)
			assert.Equal(t, 1, batch.Failed)
			return encodeErr
		})
		require.ErrorIs(t, err, encodeErr)
		assert.ErrorContains(t, err, "active ban not found")
	})
}
