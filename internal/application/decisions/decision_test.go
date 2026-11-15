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

// assertDecisionJSONState verifies that each state round trips without legacy fields.
func assertDecisionJSONState(t *testing.T, state State) {
	t.Helper()

	encoded, err := json.Marshal(Decision{ID: "stable", State: state})
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"state":"`+string(state)+`"`)
	assert.NotContains(t, string(encoded), `"active"`)
	assert.NotContains(t, string(encoded), `"failures"`)

	var decoded Decision
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, state, decoded.State)
}

func TestDecisionJSONState(t *testing.T) {
	t.Parallel()

	t.Run("banned", func(t *testing.T) {
		t.Parallel()

		assertDecisionJSONState(t, StateBanned)
	})

	t.Run("unbanned", func(t *testing.T) {
		t.Parallel()

		assertDecisionJSONState(t, StateUnbanned)
	})
}
