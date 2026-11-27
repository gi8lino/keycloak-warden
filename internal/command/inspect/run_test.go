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

	"github.com/gi8lino/keycloak-warden/pkg/model"
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

		var records []inspection
		err := Run(t.Context(), server.URL, "admin-secret", []string{"id-two", "id-one"}, func(value any) error {
			var ok bool
			records, ok = value.([]inspection)
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

func TestRunClientValidation(t *testing.T) {
	t.Parallel()

	t.Run("missing token prevents encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", []string{"one"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("invalid URL prevents encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://warden.example.com", "admin", []string{"one"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "HTTPS")
		assert.False(t, encoded)
	})

	t.Run("empty IDs return an empty list without API requests", func(t *testing.T) {
		t.Parallel()
		called := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "admin", nil, func(value any) error {
			called = true
			list, ok := value.([]inspection)
			require.True(t, ok)
			assert.Empty(t, list)
			return nil
		})
		require.NoError(t, err)
		assert.True(t, called)
	})
}

func TestRunPage(t *testing.T) {
	t.Parallel()

	t.Run("rejects nonpositive pages", func(t *testing.T) {
		t.Parallel()
		err := RunPage(t.Context(), "http://127.0.0.1:8080", "secret", []string{"one"}, 0, false, func(any) error { return nil })
		require.ErrorContains(t, err, "positive")
	})

	t.Run("rejects page selection with all history", func(t *testing.T) {
		t.Parallel()
		err := RunPage(t.Context(), "http://127.0.0.1:8080", "secret", []string{"one"}, 2, true, func(any) error { return nil })
		require.ErrorContains(t, err, "cannot be combined")
	})

	t.Run("fetches page 100 directly", func(t *testing.T) {
		t.Parallel()
		requests := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests <- r.URL.Query().Get("history-page")
			_, _ = w.Write([]byte(`{"decision":{"id":"one"},"historyPage":100,"deliveryHistory":[]}`))
		}))
		defer server.Close()

		var result []inspection
		err := RunPage(t.Context(), server.URL, "secret", []string{"one"}, 100, false, func(value any) error {
			result = value.([]inspection)
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, "100", <-requests)
		require.Len(t, result, 1)
		assert.Equal(t, 100, result[0].HistoryPage)
		assert.Equal(t, "one", result[0].Decision.ID)
		assert.Empty(t, result[0].Deliveries)
	})

	t.Run("fetches and combines every page", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		var pages []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("history-page")
			mu.Lock()
			pages = append(pages, page)
			mu.Unlock()
			switch page {
			case "":
				assert.Empty(t, r.URL.Query().Get("history-through-revision"))
				_, _ = w.Write([]byte(`{"decision":{"id":"one","revision":3},"historyPage":1,"historyNextPage":2,"deliveryHistory":[{"revision":3,"destination":"edge"}]}`))
			case "2":
				assert.Equal(t, "3", r.URL.Query().Get("history-through-revision"))
				_, _ = w.Write([]byte(`{"decision":{"id":"one"},"historyPage":2,"historyNextPage":3,"deliveryHistory":[{"revision":2,"destination":"edge"}]}`))
			case "3":
				assert.Equal(t, "3", r.URL.Query().Get("history-through-revision"))
				_, _ = w.Write([]byte(`{"decision":{"id":"one"},"historyPage":3,"deliveryHistory":[{"revision":1,"destination":"edge"}]}`))
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer server.Close()

		var result []inspection
		err := RunPage(t.Context(), server.URL, "secret", []string{"one"}, 1, true, func(value any) error {
			result = value.([]inspection)
			return nil
		})
		require.NoError(t, err)
		mu.Lock()
		assert.Equal(t, []string{"", "2", "3"}, pages)
		mu.Unlock()
		require.Len(t, result, 1)
		history, ok := result[0].Deliveries.([]model.Delivery)
		require.True(t, ok)
		require.Len(t, history, 3)
		assert.EqualValues(t, 3, history[0].Revision)
		assert.EqualValues(t, 1, history[2].Revision)
		assert.Zero(t, result[0].HistoryNextPage)
	})
}
