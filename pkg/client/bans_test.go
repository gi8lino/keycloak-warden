package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			assert.NoError(t, json.NewEncoder(w).Encode(Record{HistoryPage: 100}))
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
