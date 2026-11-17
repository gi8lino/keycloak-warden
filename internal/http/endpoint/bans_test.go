package endpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/http/endpoint"
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
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

// scriptedAdministration exercises the HTTP adapter without requiring SQLite.
type scriptedAdministration struct {
	// record is returned for successful operations.
	record bans.Record
	// records is returned when listing active decisions.
	records []bans.Record
	// err is returned from all operations to test HTTP error mapping.
	err error
	// requested captures the submitted manual-ban payload.
	requested bans.ManualBanRequest
	// id captures the decision selected for retrieval or release.
	id string
	// page records the requested history page.
	page int
	// calls counts application operations invoked after input validation.
	calls int
}

// BanManual captures the request and returns the scripted outcome.
func (s *scriptedAdministration) BanManual(_ context.Context, request bans.ManualBanRequest, _ time.Time) (bans.Record, error) {
	s.calls++
	s.requested = request
	return s.record, s.err
}

// Release captures the selected decision and returns the scripted outcome.
func (s *scriptedAdministration) Release(_ context.Context, id string, _ time.Time) (bans.Record, error) {
	s.calls++
	s.id = id
	return s.record, s.err
}

// ListActive records the read and returns the scripted active decisions.
func (s *scriptedAdministration) ListActive(context.Context, time.Time) ([]bans.Record, error) {
	s.calls++
	return s.records, s.err
}

// GetDecisionPage captures the history selection and returns the scripted record.
func (s *scriptedAdministration) GetDecisionPage(_ context.Context, id string, _ time.Time, page int, throughRevision int64) (bans.Record, error) {
	s.calls++
	s.id = id
	s.page = page
	return s.record, s.err
}

func TestCreateBan(t *testing.T) {
	t.Parallel()

	t.Run("accepts one ban request and writes the decision", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{record: bans.Record{Decision: decisions.Decision{
			ID: "decision-id", IP: "203.0.113.10", State: decisionstate.StateBanned,
		}}}
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		request := httptest.NewRequest(http.MethodPost, "/bans", strings.NewReader(`{"ipAddress":"203.0.113.10","duration":"1h","reason":"investigation"}`))
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		response := httptest.NewRecorder()
		endpoint.CreateBan(service, logger)(response, request)

		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, 1, service.calls)
		assert.Equal(t, bans.ManualBanRequest{IP: "203.0.113.10", Duration: time.Hour, Reason: "investigation"}, service.requested)
		var result bans.Record
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		assert.Equal(t, "decision-id", result.Decision.ID)
		assert.Contains(t, logs.String(), `"event":"manual_ban_requested"`)
	})

	t.Run("rejects invalid duration before calling the application", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodPost, "/bans", strings.NewReader(`{"ipAddress":"203.0.113.10","duration":"never","reason":"test"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		endpoint.CreateBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.calls)
		assert.Contains(t, response.Body.String(), "Invalid ban duration")
	})

	t.Run("missing media type", func(t *testing.T) {
		t.Parallel()

		assertRejectedBanRequest(t, "", "{}", http.StatusUnsupportedMediaType)
	})
	t.Run("wrong media type", func(t *testing.T) {
		t.Parallel()

		assertRejectedBanRequest(t, "text/plain", "{}", http.StatusUnsupportedMediaType)
	})
	t.Run("unknown field", func(t *testing.T) {
		t.Parallel()

		assertRejectedBanRequest(t, "application/json", "{\"duration\":\"1h\",\"extra\":\"unexpected\"}", http.StatusBadRequest)
	})
	t.Run("JSON array", func(t *testing.T) {
		t.Parallel()

		assertRejectedBanRequest(t, "application/json", "[]", http.StatusBadRequest)
	})
	t.Run("trailing junk", func(t *testing.T) {
		t.Parallel()

		assertRejectedBanRequest(t, "application/json", "{\"duration\":\"1h\"}garbage", http.StatusBadRequest)
	})

}

func TestBanAdministrationHandlers(t *testing.T) {
	t.Parallel()

	t.Run("list active", func(t *testing.T) {
		t.Parallel()

		assertBanAdministrationHandler(t, http.MethodGet, "/bans", endpoint.ListBans, "", false)
	})

	t.Run("inspect decision", func(t *testing.T) {
		t.Parallel()

		assertBanAdministrationHandler(t, http.MethodGet, "/bans/decision-id", endpoint.GetBan, "", true)
	})

	t.Run("release decision", func(t *testing.T) {
		t.Parallel()

		assertBanAdministrationHandler(t, http.MethodDelete, "/bans/decision-id", endpoint.DeleteBan, `"event":"ban_sources_removed"`, true)
	})
}

// assertRejectedBanRequest verifies malformed input never reaches the application service.
func assertRejectedBanRequest(t *testing.T, contentType, body string, status int) {
	t.Helper()

	service := &scriptedAdministration{}
	request := httptest.NewRequest(http.MethodPost, "/bans", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	response := httptest.NewRecorder()
	endpoint.CreateBan(service, slog.Default())(response, request)

	assert.Equal(t, status, response.Code)
	assert.Zero(t, service.calls)
}

// assertBanAdministrationHandler checks successful HTTP adaptation and optional audit logging.
func assertBanAdministrationHandler(t *testing.T, method, path string, handler func(endpoint.BanAdministration, *slog.Logger) http.HandlerFunc, wantLog string, wantID bool) {
	t.Helper()

	record := bans.Record{Decision: decisions.Decision{
		ID:    "decision-id",
		IP:    "203.0.113.10",
		State: decisionstate.StateBanned,
	}}
	service := &scriptedAdministration{
		record:  record,
		records: []bans.Record{record},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	request := httptest.NewRequest(method, path, nil)
	request.SetPathValue("id", "decision-id")
	response := httptest.NewRecorder()
	handler(service, logger)(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, 1, service.calls)
	assert.Contains(t, response.Body.String(), "decision-id")
	if wantID {
		assert.Equal(t, "decision-id", service.id)
	}
	if wantLog != "" {
		assert.Contains(t, logs.String(), wantLog)
	} else {
		assert.Empty(t, logs.String())
	}
}

// assertBanAdministrationError checks each operation's application-error mapping.
func assertBanAdministrationError(t *testing.T, method, path, body string, handler func(endpoint.BanAdministration, *slog.Logger) http.HandlerFunc, operationErr error, status int) {
	t.Helper()

	service := &scriptedAdministration{err: operationErr}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("id", "decision-id")
	response := httptest.NewRecorder()
	handler(service, logger)(response, request)

	assert.Equal(t, status, response.Code)
	assert.Equal(t, 1, service.calls)
	if status == http.StatusServiceUnavailable {
		assert.NotContains(t, response.Body.String(), "private database error")
		assert.Contains(t, logs.String(), "private database error")
	} else {
		assert.Empty(t, logs.String())
	}
}

func TestBanAdministrationErrors(t *testing.T) {
	t.Parallel()

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		t.Run("invalid input", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodPost, "/bans", "{\"ipAddress\":\"203.0.113.10\",\"duration\":\"1h\",\"reason\":\"test\"}", endpoint.CreateBan, bans.ErrInvalid, http.StatusBadRequest)
		})

		t.Run("missing decision", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodPost, "/bans", "{\"ipAddress\":\"203.0.113.10\",\"duration\":\"1h\",\"reason\":\"test\"}", endpoint.CreateBan, bans.ErrNotFound, http.StatusNotFound)
		})

		t.Run("storage unavailable", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodPost, "/bans", "{\"ipAddress\":\"203.0.113.10\",\"duration\":\"1h\",\"reason\":\"test\"}", endpoint.CreateBan, errors.New("private database error"), http.StatusServiceUnavailable)
		})
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()

		t.Run("invalid input", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodGet, "/bans", "", endpoint.ListBans, bans.ErrInvalid, http.StatusBadRequest)
		})

		t.Run("missing decision", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodGet, "/bans", "", endpoint.ListBans, bans.ErrNotFound, http.StatusNotFound)
		})

		t.Run("storage unavailable", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodGet, "/bans", "", endpoint.ListBans, errors.New("private database error"), http.StatusServiceUnavailable)
		})
	})

	t.Run("get", func(t *testing.T) {
		t.Parallel()

		t.Run("invalid input", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodGet, "/bans/decision-id", "", endpoint.GetBan, bans.ErrInvalid, http.StatusBadRequest)
		})

		t.Run("missing decision", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodGet, "/bans/decision-id", "", endpoint.GetBan, bans.ErrNotFound, http.StatusNotFound)
		})

		t.Run("storage unavailable", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodGet, "/bans/decision-id", "", endpoint.GetBan, errors.New("private database error"), http.StatusServiceUnavailable)
		})
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()

		t.Run("invalid input", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodDelete, "/bans/decision-id", "", endpoint.DeleteBan, bans.ErrInvalid, http.StatusBadRequest)
		})

		t.Run("missing decision", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodDelete, "/bans/decision-id", "", endpoint.DeleteBan, bans.ErrNotFound, http.StatusNotFound)
		})

		t.Run("storage unavailable", func(t *testing.T) {
			t.Parallel()

			assertBanAdministrationError(t, http.MethodDelete, "/bans/decision-id", "", endpoint.DeleteBan, errors.New("private database error"), http.StatusServiceUnavailable)
		})
	})
}

func TestGetBanHistoryPageValidation(t *testing.T) {
	t.Parallel()

	t.Run("rejects duplicate page parameters", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodGet, "/bans/one?history-page=1&history-page=2", nil)
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()

		endpoint.GetBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.calls)
	})

	t.Run("rejects malformed URL encoding", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodGet, "/bans/one", nil)
		request.URL.RawQuery = "history-page=%"
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()

		endpoint.GetBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.calls)
	})

	t.Run("rejects nonnumeric page", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodGet, "/bans/one?history-page=nope", nil)
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()

		endpoint.GetBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.calls)
	})

	t.Run("maps an invalid application page to bad request", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{err: bans.ErrInvalid}
		request := httptest.NewRequest(http.MethodGet, "/bans/one?history-page=-1", nil)
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()
		endpoint.GetBan(service, slog.Default())(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Equal(t, -1, service.page)
	})
	t.Run("rejects missing page value", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodGet, "/bans/one?history-page=", nil)
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()

		endpoint.GetBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Zero(t, service.calls)
	})

	t.Run("passes page 100 directly to the application", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodGet, "/bans/one?history-page=100", nil)
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()

		endpoint.GetBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, 1, service.calls)
		assert.Equal(t, "one", service.id)
		assert.Equal(t, 100, service.page)
	})

	t.Run("defaults to first page", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{}
		request := httptest.NewRequest(http.MethodGet, "/bans/one", nil)
		request.SetPathValue("id", "one")
		response := httptest.NewRecorder()

		endpoint.GetBan(service, slog.Default())(response, request)

		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, 1, service.page)
	})
}
