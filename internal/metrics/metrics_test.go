package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	t.Parallel()

	t.Run("disabled registry has no exposition", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(false, "test")
		response := httptest.NewRecorder()
		registry.Metrics().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

		assert.Equal(t, http.StatusNotFound, response.Code)
	})

	t.Run("enabled registry includes build and Go collectors", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "v1.2.3")
		output := scrape(t, registry)

		assert.Contains(t, output, `warden_build_info{version="v1.2.3"} 1`)
		assert.Contains(t, output, "go_goroutines")
		// Process metrics vary by operating system; Go metrics are portable.
	})
}

func TestInstrumentHTTP(t *testing.T) {
	t.Parallel()

	t.Run("records stable matched routes and final status", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		mux := http.NewServeMux()
		mux.HandleFunc("GET /bans/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		handler := registry.InstrumentHTTP(mux)

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bans/private-id", nil))
		require.Equal(t, http.StatusNoContent, response.Code)

		output := scrape(t, registry)
		assert.Contains(t, output, `warden_http_requests_total{code="204",method="GET",route="/bans/{id}"} 1`)
		assert.Contains(t, output, `warden_http_request_duration_seconds_count{method="GET",route="/bans/{id}"} 1`)
		assert.NotContains(t, output, "private-id")
	})

	t.Run("unmatched request never exposes raw path", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(true, "test")
		handler := registry.InstrumentHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private/client-address", nil))
		require.Equal(t, http.StatusForbidden, response.Code)

		output := scrape(t, registry)
		assert.Contains(t, output, `warden_http_requests_total{code="403",method="GET",route="unmatched"} 1`)
		assert.NotContains(t, output, "client-address")
	})

	t.Run("disabled instrumentation is transparent", func(t *testing.T) {
		t.Parallel()

		registry := NewRegistry(false, "test")
		handler := registry.InstrumentHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test", nil))
		assert.Equal(t, http.StatusNoContent, response.Code)
	})
}

// scrape reads the Prometheus exposition for one metrics test.
func scrape(t *testing.T, registry *Registry) string {
	t.Helper()

	response := httptest.NewRecorder()
	registry.Metrics().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, response.Code)
	result := response.Result()
	defer result.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	return strings.TrimSpace(string(body))
}

func TestMethodLabelCardinality(t *testing.T) {
	t.Parallel()
	t.Run("arbitrary methods share one label", func(t *testing.T) {
		t.Parallel()
		registry := NewRegistry(true, "test")
		handler := registry.InstrumentHTTP(http.NotFoundHandler())
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("CUSTOM-A", "/", nil))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("CUSTOM-B", "/", nil))
		text := scrape(t, registry)
		assert.Contains(t, text, `warden_http_requests_total{code="404",method="OTHER",route="unmatched"} 2`)
		assert.NotContains(t, text, "CUSTOM-A")
		assert.NotContains(t, text, "CUSTOM-B")
	})
}
