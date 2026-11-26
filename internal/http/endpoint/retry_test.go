package endpoint

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
)

// retryOperation records the parsed request and returns a configurable service outcome.
type retryOperation struct {
	// request captures the request forwarded to the application.
	request actions.RetryRequest
	// err is the application outcome.
	err error
}

// Retry records the request without touching a destination.
func (s *retryOperation) Retry(_ context.Context, request actions.RetryRequest, _ time.Time) error {
	s.request = request
	return s.err
}

func TestRetryEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("accepted means queued not delivered", func(t *testing.T) {
		t.Parallel()
		service := &retryOperation{}
		request := httptest.NewRequest(http.MethodPost, "/deliveries/retry", strings.NewReader(`{"decisionId":"one","revision":4,"destination":"edge","actor":"operator"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		RetryDelivery(service, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusAccepted, response.Code)
		assert.JSONEq(t, `{"queued":true}`, response.Body.String())
		assert.Equal(t, actions.RetryRequest{DecisionID: "one", Revision: 4, Destination: "edge", Actor: "operator"}, service.request)
	})

	t.Run("stale revision is a conflict", func(t *testing.T) {
		t.Parallel()
		service := &retryOperation{err: actions.ErrRetryConflict}
		request := httptest.NewRequest(http.MethodPost, "/deliveries/retry", strings.NewReader(`{"decisionId":"one","revision":4,"destination":"edge","actor":"operator"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		RetryDelivery(service, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		assert.Equal(t, http.StatusConflict, response.Code)
	})

	t.Run("rejects unknown JSON fields", func(t *testing.T) {
		t.Parallel()
		service := &retryOperation{}
		request := httptest.NewRequest(http.MethodPost, "/deliveries/retry", strings.NewReader(`{"unknown":true}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		RetryDelivery(service, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)
		require.Equal(t, http.StatusBadRequest, response.Code)
		assert.Empty(t, service.request)
	})
}
