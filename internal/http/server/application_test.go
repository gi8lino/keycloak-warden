package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/actions"
	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/providers/webhook"
	"github.com/gi8lino/keycloak-warden/internal/signing"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

// noOpBanAdministration provides inert ban operations for route authentication tests.
type noOpBanAdministration struct{}

// BanManual returns an empty ban for authentication tests.
func (noOpBanAdministration) BanManual(context.Context, bans.ManualBanRequest, time.Time) (bans.Record, error) {
	return bans.Record{}, nil
}

// Release returns an empty release for authentication tests.
func (noOpBanAdministration) Release(context.Context, string, time.Time) (bans.Record, error) {
	return bans.Record{}, nil
}

// ListActive returns an empty active-ban list for authentication tests.
func (noOpBanAdministration) ListActive(context.Context, time.Time) ([]bans.Record, error) {
	return []bans.Record{}, nil
}

// GetDecision returns an empty decision for authentication tests.
func (noOpBanAdministration) GetDecision(context.Context, string, time.Time) (bans.Record, error) {
	return bans.Record{}, nil
}

// adminRequest sends one authenticated application request for a single subtest.
func adminRequest(application http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	application.ServeHTTP(rec, req)
	return rec
}

// liveBanHandlers constructs a fresh SQLite store for each isolated subtest.
func liveBanHandlers(t *testing.T) (http.Handler, http.Handler) {
	t.Helper()
	store, err := sqlite.Open(
		filepath.Join(t.TempDir(), "warden.db"),
		detection.Rule{
			Threshold: 2,
			Window:    time.Minute,
			Ban:       time.Minute,
		},
		[]string{"edge"},
	)

	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	service, err := bans.NewAdminService(store)

	require.NoError(t, err)
	h := newTestServer(server.Config{
		Logger:     slog.Default(),
		Secret:     "snitch-secret",
		AdminToken: "admin-token",
		Readiness:  store,
		Processor:  noopProcessor{},
		BanAdmin:   service,
	})
	return h.Application, h.Management
}

// awaitDecision bounds how long the signed-delivery integration test waits.
func awaitDecision(t *testing.T, received <-chan decisions.Decision) decisions.Decision {
	t.Helper()
	select {
	case decision := <-received:
		return decision
	case <-time.After(8 * time.Second):
		require.FailNow(t, "timed out waiting for destination")
		return decisions.Decision{}
	}
}

func TestNewApplication(t *testing.T) {
	t.Parallel()

	t.Run("rejects requests without administrator token", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)

		assert.Equal(t, http.StatusUnauthorized, adminRequest(
			application,
			http.MethodPost,
			"/bans",
			"",
			`{"ipAddress":"203.0.113.40","duration":"1h","reason":"investigation"}`,
		).Code)
	})

	t.Run("rejects Snitch secret as administrator token", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)

		assert.Equal(t, http.StatusUnauthorized, adminRequest(
			application,
			http.MethodPost,
			"/bans",
			"snitch-secret",
			`{"ipAddress":"203.0.113.40","duration":"1h","reason":"investigation"}`,
		).Code)
	})

	t.Run("rejects incorrect administrator token", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)

		assert.Equal(t, http.StatusUnauthorized, adminRequest(
			application,
			http.MethodPost,
			"/bans",
			"wrong",
			`{"ipAddress":"203.0.113.40","duration":"1h","reason":"investigation"}`,
		).Code)
	})

	t.Run("creates lists inspects and removes a manual ban", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)
		created := adminRequest(
			application,
			http.MethodPost,
			"/bans",
			"admin-token",
			`{"ipAddress":"203.0.113.40","duration":"1h","reason":"investigation"}`,
		)

		require.Equal(t, http.StatusOK, created.Code, created.Body.String())
		var view bans.Record

		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &view))
		assert.Equal(t, decisions.StateBanned, view.Decision.State)
		require.Len(t, view.Sources, 1)
		assert.Equal(t, bans.SourceManual, view.Sources[0].Kind)
		listed := adminRequest(application, http.MethodGet, "/bans", "admin-token", "")

		require.Equal(t, http.StatusOK, listed.Code)
		var all []bans.Record

		require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &all))
		require.Len(t, all, 1)
		assert.Equal(t, view.Decision.ID, all[0].Decision.ID)
		id := view.Decision.ID
		get := adminRequest(application, http.MethodGet, "/bans/"+id, "admin-token", "")

		assert.Equal(t, http.StatusOK, get.Code)
		removed := adminRequest(application, http.MethodDelete, "/bans/"+id, "admin-token", "")

		require.Equal(t, http.StatusOK, removed.Code, removed.Body.String())
		require.NoError(t, json.Unmarshal(removed.Body.Bytes(), &view))
		assert.Equal(t, decisions.StateUnbanned, view.Decision.State)
		assert.Empty(t, view.Sources)
		assert.Len(t, view.Deliveries, 1)
		duplicate := adminRequest(application, http.MethodDelete, "/bans/"+id, "admin-token", "")

		assert.Equal(t, http.StatusNotFound, duplicate.Code)
	})

	t.Run("lists automatic source and unbans it through the application API", func(t *testing.T) {
		t.Parallel()

		rule := detection.Rule{
			Threshold: 2,
			Window:    time.Minute,
			Ban:       time.Minute,
		}
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"), rule, []string{"edge"})

		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		ingest, err := ingestion.New(store, rule)

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		input := func(id string) events.Envelope {
			return events.Envelope{
				ID:        id,
				Version:   1,
				Source:    "keycloak",
				Kind:      "LOGIN_ERROR",
				IP:        "203.0.113.22",
				Timestamp: now,
			}
		}
		_, err = ingest.Process(t.Context(), input("first"), now)

		require.NoError(t, err)
		auto, err := ingest.Process(t.Context(), input("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)
		service, err := bans.NewAdminService(store)

		require.NoError(t, err)
		application := newTestServer(server.Config{
			Secret:     "snitch",
			AdminToken: "admin-token",
			Logger:     slog.Default(),
			BanAdmin:   service,
			Processor:  ingest,
			Readiness:  store,
		}).Application

		listed := adminRequest(application, http.MethodGet, "/bans", "admin-token", "")

		require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
		var all []bans.Record

		require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &all))
		require.Len(t, all, 1)
		require.Len(t, all[0].Sources, 1)
		assert.Equal(t, bans.SourceAutomatic, all[0].Sources[0].Kind)

		removed := adminRequest(application, http.MethodDelete, "/bans/"+auto.ID, "admin-token", "")

		require.Equal(t, http.StatusOK, removed.Code, removed.Body.String())
		var view bans.Record

		require.NoError(t, json.Unmarshal(removed.Body.Bytes(), &view))
		assert.Equal(t, decisions.StateUnbanned, view.Decision.State)
		assert.Empty(t, view.Sources)
		job, err := store.Next(t.Context(), time.Now())

		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, decisions.StateUnbanned, job.Decision.State)
	})

	t.Run("ban routes disabled without admin token", func(t *testing.T) {
		t.Parallel()

		h := newTestServer(server.Config{
			Secret:    "secret",
			Logger:    slog.Default(),
			Processor: noopProcessor{},
			Readiness: readiness(true),
		})

		assert.Equal(t, http.StatusNotFound, adminRequest(h.Application, http.MethodPost, "/bans", "", "").Code)
		assert.Equal(t, http.StatusNotFound, adminRequest(h.Application, http.MethodGet, "/bans", "", "").Code)
		assert.Equal(t, http.StatusNotFound, adminRequest(h.Application, http.MethodGet, "/bans/id", "", "").Code)
		assert.Equal(t, http.StatusNotFound, adminRequest(h.Application, http.MethodDelete, "/bans/id", "", "").Code)
	})

	t.Run("rejects duplicate authorization headers", func(t *testing.T) {
		t.Parallel()

		h := newTestServer(server.Config{
			Secret:     "secret",
			Logger:     slog.Default(),
			Processor:  noopProcessor{},
			Readiness:  readiness(true),
			AdminToken: "admin",
			BanAdmin:   noOpBanAdministration{},
		})
		req := httptest.NewRequest(http.MethodPost, "/bans", nil)
		req.Header.Add("Authorization", "Bearer admin")
		req.Header.Add("Authorization", "Bearer admin")
		rec := httptest.NewRecorder()
		h.Application.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects basic authorization", func(t *testing.T) {
		t.Parallel()

		h := newTestServer(server.Config{
			Secret:     "secret",
			Logger:     slog.Default(),
			Processor:  noopProcessor{},
			Readiness:  readiness(true),
			AdminToken: "admin",
			BanAdmin:   noOpBanAdministration{},
		})
		req := httptest.NewRequest(http.MethodGet, "/bans", nil)
		req.Header.Set("Authorization", "Basic admin")
		rec := httptest.NewRecorder()
		h.Application.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects unknown bearer token on GET and DELETE", func(t *testing.T) {
		t.Parallel()

		h := newTestServer(server.Config{
			Secret:     "secret",
			Logger:     slog.Default(),
			Processor:  noopProcessor{},
			Readiness:  readiness(true),
			AdminToken: "admin",
			BanAdmin:   noOpBanAdministration{},
		})

		assert.Equal(t, http.StatusUnauthorized, adminRequest(h.Application, http.MethodGet, "/bans", "secret", "").Code)
		assert.Equal(
			t,
			http.StatusUnauthorized,
			adminRequest(h.Application, http.MethodGet, "/bans/id", "secret", "").Code,
		)
		assert.Equal(
			t,
			http.StatusUnauthorized,
			adminRequest(h.Application, http.MethodDelete, "/bans/id", "secret", "").Code,
		)
	})

	t.Run("management has no ban routes", func(t *testing.T) {
		t.Parallel()

		_, management := liveBanHandlers(t)

		assert.Equal(t, http.StatusNotFound, adminRequest(management, http.MethodPost, "/bans", "admin-token", "").Code)
		assert.Equal(t, http.StatusNotFound, adminRequest(management, http.MethodGet, "/bans", "admin-token", "").Code)
		assert.Equal(t, http.StatusNotFound, adminRequest(management, http.MethodGet, "/bans/id", "admin-token", "").Code)
		assert.Equal(
			t,
			http.StatusNotFound,
			adminRequest(management, http.MethodDelete, "/bans/id", "admin-token", "").Code,
		)
	})

	t.Run("signed incoming events deliver block and subsequent release", func(t *testing.T) {
		t.Parallel()

		received := make(chan decisions.Decision, 4)
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			assert.Equal(t, "expected", r.Header.Get("X-API-Key"))
			var d decisions.Decision
			if !assert.NoError(t, json.Unmarshal(body, &d)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			received <- d
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		rule := detection.Rule{
			Window:    time.Minute,
			Threshold: 1,
			Ban:       3 * time.Second,
		}
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"), rule, []string{"notify"})

		require.NoError(t, err)
		defer store.Close() //nolint:errcheck
		destinations := map[string]actions.Provider{
			"notify": webhook.Provider{
				URL:     target.URL,
				Client:  target.Client(),
				Headers: http.Header{"X-Api-Key": {"expected"}},
			},
		}
		runner := actions.Start(t.Context(), store, destinations, slog.Default())
		defer func() { require.NoError(t, runner.Close()) }()
		body := `{"id":"real-format","timestamp":"2026-11-05T00:00:00Z","schemaVersion":1,"source":"keycloak","type":"LOGIN_ERROR","ipAddress":"203.0.113.8"}`
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Snitch-Timestamp", ts)
		req.Header.Set("X-Snitch-Signature", signing.Signature("inbound", ts, []byte(body)))
		processor, err := ingestion.New(store, rule)

		require.NoError(t, err)
		rec := httptest.NewRecorder()
		newTestServer(server.Config{
			Secret:    "inbound",
			Logger:    slog.Default(),
			Processor: processor,
			Readiness: store,
		}).Application.ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
		block := awaitDecision(t, received)

		assert.Equal(t, decisions.StateBanned, block.State)
		release := awaitDecision(t, received)

		assert.Equal(t, decisions.StateUnbanned, release.State)
		assert.Equal(t, block.ID, release.ID)
		assert.Equal(t, block.Revision+1, release.Revision)
	})
}

func TestCreateBanRequestIsolation(t *testing.T) {
	t.Parallel()

	t.Run("omitted fields never inherit a preceding request", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)
		body := `{"ipAddress":"203.0.113.40","duration":"1h","reason":"investigation"}`

		require.Equal(t, http.StatusOK, adminRequest(application, http.MethodPost, "/bans", "admin-token", body).Code)
		assert.Equal(
			t,
			http.StatusBadRequest,
			adminRequest(application, http.MethodPost, "/bans", "admin-token", `{"ipAddress":"203.0.113.41"}`).Code,
		)
		assert.Equal(
			t,
			http.StatusBadRequest,
			adminRequest(application, http.MethodPost, "/bans", "admin-token", "null").Code,
		)
	})

	t.Run("concurrent requests preserve each IP", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)
		var requests sync.WaitGroup
		for n := 1; n <= 16; n++ {
			requests.Go(func() {
				ip := fmt.Sprintf("203.0.113.%d", n)
				body := fmt.Sprintf(`{"ipAddress":%q,"duration":"1h","reason":"concurrent"}`, ip)
				result := adminRequest(application, http.MethodPost, "/bans", "admin-token", body)
				if !assert.Equal(t, http.StatusOK, result.Code) {
					return
				}
				var view bans.Record
				if assert.NoError(t, json.Unmarshal(result.Body.Bytes(), &view)) {
					assert.Equal(t, ip, view.Decision.IP)
				}
			})
		}
		requests.Wait()
	})

	t.Run("raw token requires bearer scheme", func(t *testing.T) {
		t.Parallel()

		application, _ := liveBanHandlers(t)
		req := httptest.NewRequest(http.MethodGet, "/bans", nil)
		req.Header.Set("Authorization", "admin-token")
		rec := httptest.NewRecorder()
		application.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
