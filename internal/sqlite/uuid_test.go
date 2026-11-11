package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// TestDecisionIDsUseUUIDv7 ensures manual and automatic decisions receive standard UUIDv7 identifiers.
func TestDecisionIDsUseUUIDv7(t *testing.T) {
	t.Parallel()

	checkUUIDv7 := func(t *testing.T, id string) {
		t.Helper()

		parsed, err := uuid.Parse(id)
		require.NoError(t, err)
		assert.Equal(t, byte(7), parsed[6]>>4, "decision ID must use UUID version 7")
		assert.Equal(t, byte(0x80), parsed[8]&0xc0, "decision ID must use the RFC 9562 variant")
	}

	t.Run("manual ban", func(t *testing.T) {
		t.Parallel()

		store, _ := openStore(t, filepath.Join(t.TempDir(), "warden.db"))
		defer store.Close() //nolint:errcheck

		service, err := bans.NewAdminService(store)
		require.NoError(t, err)

		now := time.Now().UTC().Truncate(time.Millisecond)
		record, err := service.BanManual(t.Context(), bans.ManualBanRequest{
			IP:       "203.0.113.50",
			Duration: time.Hour,
			Reason:   "incident",
		}, now)
		require.NoError(t, err)

		checkUUIDv7(t, record.Decision.ID)
	})

	t.Run("automatic ban", func(t *testing.T) {
		t.Parallel()

		store, processor := openStore(t, filepath.Join(t.TempDir(), "warden.db"))
		defer store.Close() //nolint:errcheck

		now := time.Now().UTC().Truncate(time.Millisecond)
		_, err := processor.Process(t.Context(), failed("uuidv7-first"), now)
		require.NoError(t, err)

		decision, err := processor.Process(t.Context(), failed("uuidv7-second"), now)
		require.NoError(t, err)
		require.NotNil(t, decision)

		checkUUIDv7(t, decision.ID)
	})
}
