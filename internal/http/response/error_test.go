package response_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpkitresponse "github.com/containeroo/httpkit/response"
	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/internal/http/response"
)

func TestInternalServerError(t *testing.T) {
	t.Parallel()

	t.Run("emits safe problem with diagnostic reference", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		w := httptest.NewRecorder()

		response.InternalServerError(logger, w, errors.New("secret database detail"))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Reference:")
		assert.NotContains(t, w.Body.String(), "secret database detail")
		assert.Contains(t, logs.String(), "secret database detail")
		assert.Contains(t, logs.String(), "error_reference")
	})

	t.Run("does not append a problem after writing a response", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		tracked := httpkitresponse.NewRequestWriter(w, r)
		tracked.WriteHeader(http.StatusAccepted)

		response.InternalServerError(logger, tracked, errors.New("late failure"))

		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.True(t, strings.TrimSpace(w.Body.String()) == "")
		assert.Contains(t, logs.String(), "late failure")
	})
}
