package middleware

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	httpkitmiddleware "github.com/containeroo/httpkit/middleware"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertFailureCorrelation verifies matching problem references in access and error logs.
func assertFailureCorrelation(t *testing.T, panics bool) {
	t.Helper()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	response := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if panics {
			panic("private diagnostic")
		}
		httpresponse.InternalServerError(logger, w, errors.New("private diagnostic"))
	})
	httpkitmiddleware.Chain(
		handler,
		RequestContext(),
		httpkitmiddleware.AccessLog(logger, httpkitmiddleware.WithAccessLogFields(
			httpkitmiddleware.LogMethod,
			httpkitmiddleware.LogPath,
			httpkitmiddleware.LogStatus,
			httpkitmiddleware.LogDuration,
			httpkitmiddleware.LogErrorReference,
		)),
		RecoverPanics(logger),
	).ServeHTTP(response, httptest.NewRequest("GET", "/pages/example?secret=hidden", nil))

	require.Equal(t, 500, response.Code)
	assert.NotContains(t, response.Body.String(), "private diagnostic")
	assert.Contains(t, logs.String(), `"method":"GET"`)
	assert.Contains(t, logs.String(), `"path":"/pages/example"`)
	assert.Contains(t, logs.String(), `"status":500`)
	assert.NotContains(t, logs.String(), "hidden")
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte(`"error_reference":`)))
	assert.Contains(t, logs.String(), "private diagnostic")
}

func TestRequestFailureCorrelation(t *testing.T) {
	t.Parallel()

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		assertFailureCorrelation(t, false)
	})

	t.Run("panic", func(t *testing.T) {
		t.Parallel()

		assertFailureCorrelation(t, true)
	})
}

func TestPanicAfterResponseAbortsWithoutAppendingProblem(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("started"))
		panic("failed after write")
	})
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		httpkitmiddleware.Chain(
			handler,
			RequestContext(),
			RecoverPanics(slog.Default()),
		).ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	})
	assert.Equal(t, "started", response.Body.String())
}
