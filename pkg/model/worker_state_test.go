package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerStateValid(t *testing.T) {
	t.Parallel()

	t.Run("idle is valid", func(t *testing.T) {
		t.Parallel()
		assert.True(t, WorkerIdle.Valid())
	})

	t.Run("processing is valid", func(t *testing.T) {
		t.Parallel()
		assert.True(t, WorkerProcessing.Valid())
	})

	t.Run("stopped is valid", func(t *testing.T) {
		t.Parallel()
		assert.True(t, WorkerStopped.Valid())
	})

	t.Run("empty is invalid", func(t *testing.T) {
		t.Parallel()
		assert.False(t, WorkerState("").Valid())
	})

	t.Run("unknown is invalid", func(t *testing.T) {
		t.Parallel()
		assert.False(t, WorkerState("unknown").Valid())
	})
}

// TestWorkerStateJSON preserves the public wire-format contract used by the workers endpoint.
func TestWorkerStateJSON(t *testing.T) {
	t.Parallel()

	t.Run("marshals a named state as a string", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(WorkerProcessing)

		require.NoError(t, err)
		assert.JSONEq(t, `"processing"`, string(encoded))
	})

	t.Run("unmarshals a JSON state", func(t *testing.T) {
		t.Parallel()

		var state WorkerState
		err := json.Unmarshal([]byte(`"idle"`), &state)

		require.NoError(t, err)
		assert.Equal(t, WorkerIdle, state)
	})
}
