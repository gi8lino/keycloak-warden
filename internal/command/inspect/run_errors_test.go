package inspect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestRunClientValidation(t *testing.T) {
	t.Parallel()

	t.Run("missing token prevents encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "", []string{"one"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "admin-token")
		assert.False(t, encoded)
	})

	t.Run("invalid URL prevents encoding", func(t *testing.T) {
		t.Parallel()
		encoded := false
		err := Run(t.Context(), "http://warden.example.com", "admin", []string{"one"}, func(any) error {
			encoded = true
			return nil
		})
		require.ErrorContains(t, err, "HTTPS")
		assert.False(t, encoded)
	})

	t.Run("empty IDs return an empty list without API requests", func(t *testing.T) {
		t.Parallel()
		called := false
		err := Run(t.Context(), "http://127.0.0.1:8080", "admin", nil, func(value any) error {
			called = true
			list, ok := value.([]client.Record)
			require.True(t, ok)
			assert.Empty(t, list)
			return nil
		})
		require.NoError(t, err)
		assert.True(t, called)
	})
}
