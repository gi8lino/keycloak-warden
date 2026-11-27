package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestGetPage(t *testing.T) {
	t.Parallel()

	t.Run("requests page 100 directly", func(t *testing.T) {
		t.Parallel()
		received := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- r.URL.Query().Get("history-page")
			assert.Equal(t, "/warden/bans/id-one", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			assert.NoError(t, json.NewEncoder(w).Encode(model.Record{HistoryPage: 100}))
		}))
		defer server.Close()

		api, err := New(server.URL+"/warden", "secret")
		require.NoError(t, err)
		record, err := api.GetPage(t.Context(), "id-one", 100)
		require.NoError(t, err)
		assert.Equal(t, "100", <-received)
		assert.Equal(t, 100, record.HistoryPage)
	})

	t.Run("rejects a nonpositive page without an API call", func(t *testing.T) {
		t.Parallel()
		api, err := New("http://127.0.0.1:8080", "secret")
		require.NoError(t, err)
		_, err = api.GetPage(t.Context(), "id-one", 0)
		require.ErrorContains(t, err, "history-page")
	})
}

func TestBan(t *testing.T) {
	t.Parallel()

	t.Run("encodes the shared manual ban payload", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/bans", r.URL.Path)
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			body, err := io.ReadAll(r.Body)
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.JSONEq(t, `{"ipAddress":"203.0.113.42","duration":"15m0s","reason":"Investigation"}`, string(body))
			assert.NoError(t, json.NewEncoder(w).Encode(model.Record{Decision: model.Decision{ID: "one", State: model.DecisionBanned}}))
		}))
		t.Cleanup(server.Close)

		api, err := New(server.URL, "secret")
		require.NoError(t, err)

		result, err := api.Ban(t.Context(), ManualBanRequest{
			IP:       "203.0.113.42",
			Duration: 15 * time.Minute,
			Reason:   "Investigation",
		})

		require.NoError(t, err)
		assert.Equal(t, "one", result.Decision.ID)
		assert.Equal(t, model.DecisionBanned, result.Decision.State)
	})
}
