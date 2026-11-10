package decisions

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateValid(t *testing.T) {
	t.Parallel()
	assert.True(t, StateBanned.Valid())
	assert.True(t, StateUnbanned.Valid())
	assert.False(t, State("").Valid())
	assert.False(t, State("pending").Valid())
}

func TestDecisionJSONState(t *testing.T) {
	t.Parallel()

	for _, state := range []State{StateBanned, StateUnbanned} {
		encoded, err := json.Marshal(Decision{ID: "stable", State: state})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"state":"`+string(state)+`"`)
		assert.NotContains(t, string(encoded), `"active"`)

		var decoded Decision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, state, decoded.State)
	}
}
