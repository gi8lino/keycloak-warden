package listactive

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("lists active bans using the authenticated application API", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/warden/bans", r.URL.Path)
			assert.Equal(t, "Bearer admin-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[{"decision":{"id":"id-one"},"sources":[],"deliveries":[]}]`))
		}))
		defer server.Close()

		var records []bans.Record
		err := Run(t.Context(), server.URL+"/warden", "admin-secret", func(value any) error {
			var ok bool
			records, ok = value.([]bans.Record)
			require.True(t, ok)
			return nil
		})

		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Equal(t, "id-one", records[0].Decision.ID)
	})

	t.Run("does not encode unsuccessful API responses", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		encoded := false
		err := Run(t.Context(), server.URL, "wrong-token", func(any) error {
			encoded = true
			return nil
		})

		require.ErrorContains(t, err, "application HTTP 401")
		assert.False(t, encoded)
	})

	t.Run("propagates output encoding failures", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		}))
		defer server.Close()

		encodeErr := errors.New("output unavailable")
		err := Run(t.Context(), server.URL, "admin-secret", func(any) error {
			return encodeErr
		})

		require.ErrorIs(t, err, encodeErr)
	})
}
