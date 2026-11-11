package sqlite_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
	"github.com/gi8lino/keycloak-warden/internal/application/ingestion"
	"github.com/gi8lino/keycloak-warden/internal/sqlite"
)

func TestOpenValidation(t *testing.T) {
	t.Parallel()

	t.Run("rejects invalid rule before creating database", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.db")
		store, err := sqlite.Open(path, detection.Rule{}, nil)
		require.Error(t, err)
		assert.Nil(t, store)
	})

	t.Run("rejects missing database directory", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "missing-directory", "state.db")
		store, err := sqlite.Open(path, detection.Rule{Threshold: 2, Window: time.Minute, Ban: time.Minute}, nil)
		require.Error(t, err)
		assert.Nil(t, store)
	})
}

func TestStoreClosedErrors(t *testing.T) {
	t.Parallel()

	store, _ := openStore(t, filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, store.Close())

	assert.Error(t, store.Ping(t.Context()))
	assert.Error(t, store.Prune(t.Context(), time.Now()))
	_, err := store.Next(t.Context(), time.Now())
	assert.Error(t, err)
	_, err = store.NextDeadline(t.Context())
	assert.Error(t, err)
	_, err = store.Maintain(t.Context(), time.Now())
	assert.Error(t, err)
	assert.Error(t, store.Transact(t.Context(), func(ingestion.Transaction) error {
		return errors.New("should not be invoked")
	}))
}
