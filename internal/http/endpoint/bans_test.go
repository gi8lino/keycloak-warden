package endpoint_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
)

// assertCreateBanStatus checks the response status for a request body sent to POST /bans.
func assertCreateBanStatus(t *testing.T, body string, status int) {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/bans", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	endpoint.CreateBan(nil, logger)(response, request)

	assert.Equal(t, status, response.Code)
}

func TestCreateBanBodyValidation(t *testing.T) {
	t.Parallel()

	t.Run("rejects malformed JSON", func(t *testing.T) {
		t.Parallel()

		assertCreateBanStatus(t, "{invalid", http.StatusBadRequest)
	})

	t.Run("rejects a second JSON object", func(t *testing.T) {
		t.Parallel()

		body := `{"ipAddress":"203.0.113.1","duration":"1h","reason":"test"} {}`
		assertCreateBanStatus(t, body, http.StatusBadRequest)
	})

	t.Run("rejects oversized initial document", func(t *testing.T) {
		t.Parallel()

		body := `{"reason":"` + strings.Repeat("x", 16<<10) + `"}`
		assertCreateBanStatus(t, body, http.StatusRequestEntityTooLarge)
	})

	t.Run("rejects oversized trailing body", func(t *testing.T) {
		t.Parallel()

		body := `{"ipAddress":"203.0.113.1","duration":"1h","reason":"test"}` + strings.Repeat(" ", 16<<10)
		assertCreateBanStatus(t, body, http.StatusRequestEntityTooLarge)
	})
}
