package actions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryPolicyNextDelay(t *testing.T) {
	t.Parallel()

	t.Run("starts at ten seconds", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 10*time.Second, DefaultRetryPolicy().NextDelay(0))
	})

	t.Run("doubles the previous delay", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 20*time.Second, DefaultRetryPolicy().NextDelay(10*time.Second))
	})

	t.Run("keeps the minimum for small values", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 10*time.Second, DefaultRetryPolicy().NextDelay(time.Second))
	})

	t.Run("caps at five minutes", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 5*time.Minute, DefaultRetryPolicy().NextDelay(3*time.Minute))
	})

	t.Run("does not double at the cap", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 5*time.Minute, DefaultRetryPolicy().NextDelay(5*time.Minute))
	})
}

func TestRetryPolicyValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts defaults", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, DefaultRetryPolicy().Validate())
	})

	t.Run("accepts equal delays", func(t *testing.T) {
		t.Parallel()

		policy := RetryPolicy{
			InitialDelay: time.Millisecond,
			MaxDelay:     time.Millisecond,
		}
		require.NoError(t, policy.Validate())
	})

	t.Run("rejects zero initial delay", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.InitialDelay = 0
		require.ErrorContains(t, policy.Validate(), "retry-initial-delay")
	})

	t.Run("rejects negative initial delay", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.InitialDelay = -time.Second
		require.ErrorContains(t, policy.Validate(), "retry-initial-delay")
	})

	t.Run("rejects submillisecond initial delay", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.InitialDelay = time.Microsecond
		require.ErrorContains(t, policy.Validate(), "retry-initial-delay")
	})

	t.Run("rejects fractional millisecond maximum", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.MaxDelay += time.Microsecond
		require.ErrorContains(t, policy.Validate(), "retry-max-delay")
	})

	t.Run("rejects zero maximum delay", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.MaxDelay = 0
		require.ErrorContains(t, policy.Validate(), "retry-max-delay")
	})

	t.Run("rejects negative maximum delay", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.MaxDelay = -time.Second
		require.ErrorContains(t, policy.Validate(), "retry-max-delay")
	})

	t.Run("rejects maximum below initial delay", func(t *testing.T) {
		t.Parallel()

		policy := DefaultRetryPolicy()
		policy.MaxDelay = time.Second
		require.ErrorContains(t, policy.Validate(), "must not be less than retry-initial-delay")
	})
}

func TestRetryPolicyCustomDelays(t *testing.T) {
	t.Parallel()

	policy := RetryPolicy{
		InitialDelay: 3 * time.Second,
		MaxDelay:     11 * time.Second,
	}

	t.Run("uses custom initial delay", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 3*time.Second, policy.NextDelay(0))
	})

	t.Run("doubles the persisted delay", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 6*time.Second, policy.NextDelay(3*time.Second))
	})

	t.Run("caps at custom maximum", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 11*time.Second, policy.NextDelay(6*time.Second))
	})

	t.Run("handles a persisted delay above the new cap", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 11*time.Second, policy.NextDelay(time.Minute))
	})

	t.Run("handles a persisted delay below the new minimum", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 3*time.Second, policy.NextDelay(time.Second))
	})

	t.Run("supports constant delay", func(t *testing.T) {
		t.Parallel()

		fixed := RetryPolicy{
			InitialDelay: time.Second,
			MaxDelay:     time.Second,
		}
		assert.Equal(t, time.Second, fixed.NextDelay(time.Second))
	})

	t.Run("does not overflow when doubling a large delay", func(t *testing.T) {
		t.Parallel()

		large := RetryPolicy{
			InitialDelay: time.Second,
			MaxDelay:     (time.Duration(1<<63-1) / time.Millisecond) * time.Millisecond,
		}
		require.NoError(t, large.Validate())
		assert.Equal(t, large.MaxDelay, large.NextDelay(large.MaxDelay))
	})

	t.Run("does not round an odd maximum up prematurely", func(t *testing.T) {
		t.Parallel()

		odd := RetryPolicy{
			InitialDelay: time.Millisecond,
			MaxDelay:     5 * time.Millisecond,
		}
		assert.Equal(t, 4*time.Millisecond, odd.NextDelay(2*time.Millisecond))
	})
}
