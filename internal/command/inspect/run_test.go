package inspect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("fetches decisions in argument order using bearer authorization", func(t *testing.T) {
		t.Parallel()

		var mu sync.Mutex
		var paths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"decision":{"id":"` + strings.TrimPrefix(r.URL.Path, "/bans/") + `"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		var records []client.Record
		err := Run(t.Context(), server.URL, "admin-secret", []string{"id-two", "id-one"}, func(value any) error {
			var ok bool
			records, ok = value.([]client.Record)
			require.True(t, ok)
			return nil
		})

		require.NoError(t, err)
		mu.Lock()
		assert.Equal(t, []string{"/bans/id-two", "/bans/id-one"}, paths)
		mu.Unlock()
		require.Len(t, records, 2)
		assert.Equal(t, "id-two", records[0].Decision.ID)
		assert.Equal(t, "id-one", records[1].Decision.ID)
	})

	t.Run("stops at the first failed request without emitting a partial result", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.URL.Path == "/bans/id-two" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"decision":{"id":"id-one"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		encoded := false
		err := Run(t.Context(), server.URL, "admin-secret", []string{"id-one", "id-two", "id-three"}, func(any) error {
			encoded = true
			return nil
		})

		require.ErrorContains(t, err, `inspect decision "id-two"`)
		assert.EqualValues(t, 2, requests.Load())
		assert.False(t, encoded)
	})

	t.Run("returns context cancellation without contacting the API", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		encoded := false
		err := Run(ctx, "http://127.0.0.1:8080", "admin-secret", []string{"id-one"}, func(any) error {
			encoded = true
			return nil
		})

		require.ErrorIs(t, err, context.Canceled)
		assert.False(t, encoded)
	})

	t.Run("propagates output encoding failures", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"decision":{"id":"id-one"},"sources":[],"deliveries":[]}`))
		}))
		defer server.Close()

		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin-secret", []string{"id-one"}, func(any) error {
			return encodeErr
		})

		require.ErrorIs(t, err, encodeErr)
	})
}
