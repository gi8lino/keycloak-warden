package listactive

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunClientValidation(t *testing.T) {
	t.Parallel()

	t.Run("requires token", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("rejects insecure remote URL", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://warden.example.com", "admin", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "HTTPS")
		assert.False(t, encoded)
	})

	t.Run("canceled HTTP request does not encode", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		encoded := false
		err := Run(ctx, "http://127.0.0.1:8080", "admin", func(any) error {
			encoded = true
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.False(t, encoded)
	})
}
