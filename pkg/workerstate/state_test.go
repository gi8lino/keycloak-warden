package workerstate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateValid(t *testing.T) {
	t.Parallel()

	t.Run("idle is valid", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StateIdle.Valid())
	})

	t.Run("processing is valid", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StateProcessing.Valid())
	})

	t.Run("stopped is valid", func(t *testing.T) {
		t.Parallel()
		assert.True(t, StateStopped.Valid())
	})

	t.Run("empty is invalid", func(t *testing.T) {
		t.Parallel()
		assert.False(t, State("").Valid())
	})

	t.Run("unknown is invalid", func(t *testing.T) {
		t.Parallel()
		assert.False(t, State("unknown").Valid())
	})
}

// TestStateJSON preserves the public wire-format contract used by the workers endpoint.
func TestStateJSON(t *testing.T) {
	t.Parallel()

	t.Run("marshals a named state as a string", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(StateProcessing)

		require.NoError(t, err)
		assert.JSONEq(t, `"processing"`, string(encoded))
	})

	t.Run("unmarshals a JSON state", func(t *testing.T) {
		t.Parallel()

		var state State
		err := json.Unmarshal([]byte(`"idle"`), &state)

		require.NoError(t, err)
		assert.Equal(t, StateIdle, state)
	})
}
