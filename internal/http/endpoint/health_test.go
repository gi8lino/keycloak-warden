package endpoint_test

import (
	"context"
	"errors"
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

// healthProbe reports configured readiness failures without requiring a database.
type healthProbe struct {
	pingErr error
	called  int
}

func (p *healthProbe) Ping(context.Context) error {
	p.called++
	return p.pingErr
}

func TestHealth(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	endpoint.Health()(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
}

func TestReady(t *testing.T) {
	t.Parallel()

	t.Run("missing worker", func(t *testing.T) {
		t.Parallel()
		p := &healthProbe{}
		w := httptest.NewRecorder()
		endpoint.Ready(p, nil)(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Zero(t, p.called)
	})

	t.Run("stopped worker", func(t *testing.T) {
		t.Parallel()
		p := &healthProbe{}
		done := make(chan struct{})
		close(done)
		w := httptest.NewRecorder()
		endpoint.Ready(p, done)(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Zero(t, p.called)
	})

	t.Run("database failure", func(t *testing.T) {
		t.Parallel()
		p := &healthProbe{pingErr: errors.New("database offline")}
		w := httptest.NewRecorder()
		endpoint.Ready(p, make(chan struct{}))(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, 1, p.called)
		assert.NotContains(t, w.Body.String(), "database offline")
	})

	t.Run("healthy", func(t *testing.T) {
		t.Parallel()
		p := &healthProbe{}
		w := httptest.NewRecorder()
		endpoint.Ready(p, make(chan struct{}))(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, p.called)
		assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
	})
}
