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

func TestCreateBanBodyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "rejects malformed JSON",
			body:       "{invalid",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects a second JSON object",
			body:       `{"ipAddress":"203.0.113.1","duration":"1h","reason":"test"} {}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects oversized initial document",
			body:       `{"reason":"` + strings.Repeat("x", 16<<10) + `"}`,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "rejects oversized trailing body",
			body:       `{"ipAddress":"203.0.113.1","duration":"1h","reason":"test"}` + strings.Repeat(" ", 16<<10),
			wantStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodPost, "/bans", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			endpoint.CreateBan(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(response, request)

			assert.Equal(t, tt.wantStatus, response.Code)
		})
	}
}
