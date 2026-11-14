package actions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNextRetryDelay(t *testing.T) {
	t.Parallel()

	t.Run("starts at ten seconds", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 10*time.Second, NextRetryDelay(0))
	})

	t.Run("doubles the previous delay", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 20*time.Second, NextRetryDelay(10*time.Second))
	})

	t.Run("keeps the minimum for small values", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 10*time.Second, NextRetryDelay(time.Second))
	})

	t.Run("caps at five minutes", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 5*time.Minute, NextRetryDelay(3*time.Minute))
	})

	t.Run("does not double at the cap", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 5*time.Minute, NextRetryDelay(5*time.Minute))
	})
}
