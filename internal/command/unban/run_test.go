package unban

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clioutput "github.com/gi8lino/keycloak-warden/internal/output"
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
		var output bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			clioutput.New(textFormat(), &output),
		)

		require.NoError(t, err)
		deletedMu.Lock()
		assert.Equal(t, []string{"/bans/id-10", "/bans/id-20"}, deleted)
		deletedMu.Unlock()

		assert.EqualValues(t, 1, gets.Load())
		assert.Equal(t, "Unbanned 203.0.113.10\nUnbanned 203.0.113.20\n2 succeeded, 0 failed\n", output.String())
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
		var output bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			clioutput.New(textFormat(), &output),
		)

		require.ErrorContains(t, err, "failed 203.0.113.10")
		assert.ErrorContains(t, err, "provider unavailable")
		deletedMu.Lock()
		assert.Equal(t, []string{"/bans/id-10", "/bans/id-20"}, deleted)
		deletedMu.Unlock()

		assert.EqualValues(t, 1, gets.Load())
		assert.Equal(t, "Unbanned 203.0.113.20\n1 succeeded, 1 failed\n", output.String())
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
		var output bytes.Buffer
		err := Run(
			t.Context(),
			server.URL,
			"admin-secret",
			[]string{"203.0.113.10", "203.0.113.20"},
			clioutput.New(textFormat(), &output),
		)

		require.ErrorContains(t, err, "failed 203.0.113.10: active ban not found")
		assert.EqualValues(t, 1, deletes.Load())
		assert.Equal(t, "Unbanned 203.0.113.20\n1 succeeded, 1 failed\n", output.String())
	})

}

// textFormat provides an output format pointer for command tests.
func textFormat() *string {
	format := clioutput.FormatText
	return &format
}
