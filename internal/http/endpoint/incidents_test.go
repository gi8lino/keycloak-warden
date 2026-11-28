package endpoint

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIncidentQuery(t *testing.T) {
	t.Parallel()
	t.Run("preserves selectors", func(t *testing.T) {
		t.Parallel()
		query, err := parseIncidentQuery("before-id=42&rule=admin-audit&kind=admin")
		require.NoError(t, err)
		assert.Equal(t, overview.IncidentQuery{BeforeID: 42, Rule: "admin-audit", Kind: "admin"}, query)
	})
	t.Run("allows the newest unfiltered page", func(t *testing.T) {
		t.Parallel()
		query, err := parseIncidentQuery("")
		require.NoError(t, err)
		assert.Empty(t, query)
	})
	t.Run("rejects malformed escaping", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?rule=%ZZ", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects semicolon syntax", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?rule=a;b", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects duplicate rules", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?rule=a&rule=b", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects duplicate cursors", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?before-id=1&before-id=2", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects unknown selectors", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?page=2", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects empty cursors", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?before-id=", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects zero cursors", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?before-id=0", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
	t.Run("rejects overflowing cursors", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/incidents?before-id=9223372036854775808", nil)
		// A nil service ensures rejected input cannot reach the application layer.
		Incidents(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
	})
}
