package endpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
)

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
	// calls counts application operations invoked after input validation.
	calls int
}

func (s *scriptedAdministration) BanManual(_ context.Context, request bans.ManualBanRequest, _ time.Time) (bans.Record, error) {
	s.calls++
	s.requested = request
	return s.record, s.err
}

func (s *scriptedAdministration) Release(_ context.Context, id string, _ time.Time) (bans.Record, error) {
	s.calls++
	s.id = id
	return s.record, s.err
}

func (s *scriptedAdministration) ListActive(context.Context, time.Time) ([]bans.Record, error) {
	s.calls++
	return s.records, s.err
}

func (s *scriptedAdministration) GetDecision(_ context.Context, id string, _ time.Time) (bans.Record, error) {
	s.calls++
	s.id = id
	return s.record, s.err
}

func TestCreateBan(t *testing.T) {
	t.Parallel()

	t.Run("accepts one ban request and writes the decision", func(t *testing.T) {
		t.Parallel()
		service := &scriptedAdministration{record: bans.Record{Decision: decisions.Decision{
			ID: "decision-id", IP: "203.0.113.10", State: decisions.StateBanned,
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

	tests := []struct {
		name        string
		contentType string
		body        string
		want        int
	}{
		{name: "missing media type", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "wrong media type", contentType: "text/plain", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "unknown field", contentType: "application/json", body: `{"duration":"1h","extra":"unexpected"}`, want: http.StatusBadRequest},
		{name: "JSON array", contentType: "application/json", body: `[]`, want: http.StatusBadRequest},
		{name: "trailing junk", contentType: "application/json", body: `{"duration":"1h"}garbage`, want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service := &scriptedAdministration{}
			request := httptest.NewRequest(http.MethodPost, "/bans", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", tt.contentType)
			response := httptest.NewRecorder()
			endpoint.CreateBan(service, slog.Default())(response, request)

			assert.Equal(t, tt.want, response.Code)
			assert.Zero(t, service.calls)
		})
	}
}

func TestBanAdministrationHandlers(t *testing.T) {
	t.Parallel()

	newRecord := bans.Record{Decision: decisions.Decision{ID: "decision-id", IP: "203.0.113.10", State: decisions.StateBanned}}
	tests := []struct {
		name    string
		method  string
		path    string
		handler func(endpoint.BanAdministration, *slog.Logger) http.HandlerFunc
		wantLog string
	}{
		{name: "list active", method: http.MethodGet, path: "/bans", handler: endpoint.ListBans},
		{name: "inspect decision", method: http.MethodGet, path: "/bans/decision-id", handler: endpoint.GetBan},
		{name: "release decision", method: http.MethodDelete, path: "/bans/decision-id", handler: endpoint.DeleteBan, wantLog: `"event":"ban_sources_removed"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service := &scriptedAdministration{record: newRecord, records: []bans.Record{newRecord}}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			request := httptest.NewRequest(tt.method, tt.path, nil)
			request.SetPathValue("id", "decision-id")
			response := httptest.NewRecorder()
			tt.handler(service, logger)(response, request)

			assert.Equal(t, http.StatusOK, response.Code)
			assert.Equal(t, 1, service.calls)
			assert.Contains(t, response.Body.String(), "decision-id")
			if tt.name != "list active" {
				assert.Equal(t, "decision-id", service.id)
			}
			if tt.wantLog != "" {
				assert.Contains(t, logs.String(), tt.wantLog)
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}
}

func TestBanAdministrationErrors(t *testing.T) {
	t.Parallel()

	operations := []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(endpoint.BanAdministration, *slog.Logger) http.HandlerFunc
	}{
		{name: "create", method: http.MethodPost, path: "/bans", body: `{"ipAddress":"203.0.113.10","duration":"1h","reason":"test"}`, handler: endpoint.CreateBan},
		{name: "list", method: http.MethodGet, path: "/bans", handler: endpoint.ListBans},
		{name: "get", method: http.MethodGet, path: "/bans/decision-id", handler: endpoint.GetBan},
		{name: "delete", method: http.MethodDelete, path: "/bans/decision-id", handler: endpoint.DeleteBan},
	}
	errorsToCheck := []struct {
		name string
		err  error
		want int
	}{
		{name: "invalid input", err: bans.ErrInvalid, want: http.StatusBadRequest},
		{name: "missing decision", err: bans.ErrNotFound, want: http.StatusNotFound},
		{name: "storage unavailable", err: errors.New("private database error"), want: http.StatusServiceUnavailable},
	}

	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			for _, testCase := range errorsToCheck {
				t.Run(testCase.name, func(t *testing.T) {
					t.Parallel()
					service := &scriptedAdministration{err: testCase.err}
					var logs bytes.Buffer
					logger := slog.New(slog.NewJSONHandler(&logs, nil))
					request := httptest.NewRequest(op.method, op.path, strings.NewReader(op.body))
					request.Header.Set("Content-Type", "application/json")
					request.SetPathValue("id", "decision-id")
					response := httptest.NewRecorder()
					op.handler(service, logger)(response, request)

					assert.Equal(t, testCase.want, response.Code)
					assert.Equal(t, 1, service.calls)
					if testCase.want == http.StatusServiceUnavailable {
						assert.NotContains(t, response.Body.String(), "private database error")
						assert.Contains(t, logs.String(), "private database error")
					} else {
						assert.Empty(t, logs.String())
					}
				})
			}
		})
	}
}
