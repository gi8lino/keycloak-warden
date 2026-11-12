package ban

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestExecute(t *testing.T) {
	t.Parallel()

	t.Run("stops before the first operation when context is canceled", func(t *testing.T) {
		t.Parallel()

		client, err := client.New("http://127.0.0.1:8080", "admin-secret")
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		batch, failures := execute(ctx, client, []string{"203.0.113.10", "203.0.113.20"}, time.Hour, "incident")

		assert.Equal(t, "ban", batch.Operation)
		assert.Empty(t, batch.Results)
		assert.Zero(t, batch.Succeeded)
		assert.Zero(t, batch.Failed)
		require.Len(t, failures, 1)
		require.True(t, errors.Is(failures[0], context.Canceled))
	})
}
