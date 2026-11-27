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

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/enforcement"
	"github.com/gi8lino/keycloak-warden/internal/application/events"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/application/overview"
	"github.com/gi8lino/keycloak-warden/internal/http/server"
	"github.com/gi8lino/keycloak-warden/internal/providers/webhook"
	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/internal/signing"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// processDecision extracts the effective decision for server-storage integration tests.
func processDecision(processor *ingestion.Service, ctx context.Context, envelope events.Envelope, now time.Time) (*model.Decision, error) {
	result, err := processor.Process(ctx, envelope, func() time.Time { return now })
	return result.Decision, err
}

// noOpBanAdministration provides inert ban operations for route authentication tests.
type noOpBanAdministration struct{}

// BanManual returns an empty ban for authentication tests.
func (noOpBanAdministration) BanManual(context.Context, bans.ManualBanRequest, time.Time) (model.Record, error) {
	return model.Record{}, nil
}

// Release returns an empty release for authentication tests.
func (noOpBanAdministration) Release(context.Context, string, time.Time) (model.Record, error) {
	return model.Record{}, nil
}

// ListActive returns an empty active-ban list for authentication tests.
func (noOpBanAdministration) ListActive(context.Context, time.Time) ([]model.Record, error) {
	return []model.Record{}, nil
}

// GetDecision returns an empty decision for authentication tests.
func (noOpBanAdministration) GetDecisionPage(context.Context, string, time.Time, int, int64) (model.Record, error) {
	return model.Record{}, nil
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
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"))

	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	service, err := bans.NewAdminService(store, []string{"edge"}, bans.Policy{})

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
func awaitDecision(t *testing.T, received <-chan model.Decision) model.Decision {
	t.Helper()
	select {
	case decision := <-received:
		return decision
	case <-time.After(8 * time.Second):
		require.FailNow(t, "timed out waiting for destination")
		return model.Decision{}
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
		var view model.Record

		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &view))
		assert.Equal(t, model.DecisionBanned, view.Decision.State)
		require.Len(t, view.Sources, 1)
		assert.Equal(t, model.SourceManual, view.Sources[0].Kind)
		listed := adminRequest(application, http.MethodGet, "/bans", "admin-token", "")

		require.Equal(t, http.StatusOK, listed.Code)
		var all []model.Record

		require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &all))
		require.Len(t, all, 1)
		assert.Equal(t, view.Decision.ID, all[0].Decision.ID)
		id := view.Decision.ID
		get := adminRequest(application, http.MethodGet, "/bans/"+id, "admin-token", "")

		assert.Equal(t, http.StatusOK, get.Code)
		removed := adminRequest(application, http.MethodDelete, "/bans/"+id, "admin-token", "")

		require.Equal(t, http.StatusOK, removed.Code, removed.Body.String())
		require.NoError(t, json.Unmarshal(removed.Body.Bytes(), &view))
		assert.Equal(t, model.DecisionUnbanned, view.Decision.State)
		assert.Empty(t, view.Sources)
		assert.Len(t, view.Deliveries, 1)
		duplicate := adminRequest(application, http.MethodDelete, "/bans/"+id, "admin-token", "")

		assert.Equal(t, http.StatusNotFound, duplicate.Code)
	})

	t.Run("lists automatic source and unbans it through the application API", func(t *testing.T) {
		t.Parallel()

		rule := detection.Rule{
			Name: "brute-force",
			Selector: detection.Selector{
				Kind:   events.KindUser,
				Events: []string{events.TypeLoginError},
			},
			Aggregation: detection.Aggregation{
				GroupBy:   detection.GroupIP,
				Threshold: 2,
				Window:    time.Minute,
			},
			Actions: detection.Actions{
				Ban: time.Minute,
			},
		}
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"))

		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		ingest, err := ingestion.New(store, []detection.Rule{rule}, []string{"edge"}, bans.Policy{})

		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Millisecond)
		input := func(id string) events.Envelope {
			return events.Envelope{
				ID:        id,
				Version:   events.SchemaVersion,
				Source:    events.SourceKeycloak,
				Kind:      events.KindUser,
				Timestamp: now,
				User: &events.UserEvent{
					Type: events.TypeLoginError,
					IP:   "203.0.113.22",
				},
			}
		}
		_, err = processDecision(ingest, t.Context(), input("first"), now)

		require.NoError(t, err)
		auto, err := processDecision(ingest, t.Context(), input("second"), now)

		require.NoError(t, err)
		require.NotNil(t, auto)
		service, err := bans.NewAdminService(store, []string{"edge"}, bans.Policy{})

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
		var all []model.Record

		require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &all))
		require.Len(t, all, 1)
		require.Len(t, all[0].Sources, 1)
		assert.Equal(t, model.SourceAutomatic, all[0].Sources[0].Kind)

		removed := adminRequest(application, http.MethodDelete, "/bans/"+auto.ID, "admin-token", "")

		require.Equal(t, http.StatusOK, removed.Code, removed.Body.String())
		var view model.Record

		require.NoError(t, json.Unmarshal(removed.Body.Bytes(), &view))
		assert.Equal(t, model.DecisionUnbanned, view.Decision.State)
		assert.Empty(t, view.Sources)
		job, err := store.Next(t.Context(), time.Now())

		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, model.DecisionUnbanned, job.Decision.State)
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

		received := make(chan model.Decision, 4)
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			assert.Equal(t, "expected", r.Header.Get("X-API-Key"))
			var d model.Decision
			if !assert.NoError(t, json.Unmarshal(body, &d)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			received <- d
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		rule := detection.Rule{
			Name: "brute-force",
			Selector: detection.Selector{
				Kind:   events.KindUser,
				Events: []string{events.TypeLoginError},
			},
			Aggregation: detection.Aggregation{
				GroupBy:   detection.GroupIP,
				Window:    time.Minute,
				Threshold: 1,
			},
			Actions: detection.Actions{
				Ban: 3 * time.Second,
			},
		}
		store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"))

		require.NoError(t, err)
		defer store.Close() //nolint:errcheck
		destinations := map[string]enforcement.Target{
			"notify": {
				Provider: webhook.Provider[model.Decision]{
					Target: webhook.NewTarget(target.URL, map[string]string{"X-Api-Key": "expected"}, target.Client(), nil),
				},
				MaxAttempts: retry.DefaultMaxAttempts,
			},
		}
		expirer, err := bans.NewExpiryService(store, []string{"notify"})
		require.NoError(t, err)
		runner := enforcement.Start(t.Context(), store, expirer, destinations, retry.DefaultRetryPolicy(), slog.Default())
		defer func() { require.NoError(t, runner.Close()) }()
		body := `{"schemaVersion":2,"id":"real-format","source":"keycloak","timestamp":"2026-11-05T00:00:00Z","kind":"user","user":{"type":"LOGIN_ERROR","ipAddress":"203.0.113.8"}}`
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Snitch-Timestamp", ts)
		req.Header.Set("X-Snitch-Signature", signing.Signature("inbound", ts, []byte(body)))
		processor, err := ingestion.New(store, []detection.Rule{rule}, []string{"notify"}, bans.Policy{})

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

		assert.Equal(t, model.DecisionBanned, block.State)
		release := awaitDecision(t, received)

		assert.Equal(t, model.DecisionUnbanned, release.State)
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
				var view model.Record
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

func TestIncidentsRoute(t *testing.T) {
	t.Parallel()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "warden.db"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	operations, err := overview.NewService(store)
	require.NoError(t, err)
	processor, err := ingestion.New(store, []detection.Rule{{
		Name: "admin-audit",
		Selector: detection.Selector{
			Kind: events.KindAdmin,
		},
		Aggregation: detection.Aggregation{
			GroupBy:   detection.GroupRealm,
			Threshold: 1,
			Window:    time.Minute,
		},
	}}, nil, bans.Policy{})
	require.NoError(t, err)
	application := newTestServer(server.Config{
		Logger:     slog.Default(),
		Secret:     "snitch-secret",
		AdminToken: "admin-token",
		Readiness:  store,
		Processor:  processor,
		Operations: operations,
	}).Application

	body := `{"schemaVersion":2,"id":"admin-event","source":"keycloak","timestamp":"2026-11-05T15:00:00Z","kind":"admin","admin":{"realmId":"hq","operationType":"CREATE","resourceType":"USER","resourcePath":"users/example","actor":{"realmId":"master","clientId":null,"userId":null,"ipAddress":null}}}`
	now := strconv.FormatInt(time.Now().Unix(), 10)
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Snitch-Timestamp", now)
	request.Header.Set("X-Snitch-Signature", signing.Signature("snitch-secret", now, []byte(body)))
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())

	assert.Equal(t, http.StatusNotFound, adminRequest(application, http.MethodGet, "/observations", "admin-token", "").Code)
	assert.Equal(t, http.StatusUnauthorized, adminRequest(application, http.MethodGet, "/incidents", "", "").Code)
	assert.Equal(t, http.StatusBadRequest, adminRequest(application, http.MethodGet, "/incidents?before-id=0", "admin-token", "").Code)
	response = adminRequest(application, http.MethodGet, "/incidents?kind=admin", "admin-token", "")
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var page model.IncidentPage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	assert.Equal(t, "admin-audit", page.Items[0].Rule)
	assert.Equal(t, events.KindAdmin, page.Items[0].EventKind)
	assert.Empty(t, page.Items[0].EventType)
	assert.Equal(t, "master", page.Items[0].ActorRealmID)
}
