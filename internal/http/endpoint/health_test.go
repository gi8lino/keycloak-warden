package endpoint_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
)

func TestReadyWithoutDatabase(t *testing.T) {
	t.Parallel()

	handler := endpoint.Ready(nil, make(chan struct{}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Contains(t, response.Body.String(), "Database unavailable")
}
