package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimelineKind(t *testing.T) {
	t.Parallel()

	t.Run("source has stable wire value", func(t *testing.T) {
		t.Parallel()
		assert.True(t, TimelineSource.Valid())
		assert.Equal(t, TimelineKind("source"), TimelineSource)
	})
	t.Run("decision has stable wire value", func(t *testing.T) {
		t.Parallel()
		assert.True(t, TimelineDecision.Valid())
		assert.Equal(t, TimelineKind("decision"), TimelineDecision)
	})
	t.Run("attempt has stable wire value", func(t *testing.T) {
		t.Parallel()
		assert.True(t, TimelineAttempt.Valid())
		assert.Equal(t, TimelineKind("attempt"), TimelineAttempt)
	})
	t.Run("retry has stable wire value", func(t *testing.T) {
		t.Parallel()
		assert.True(t, TimelineRetry.Valid())
		assert.Equal(t, TimelineKind("retry"), TimelineRetry)
	})
	t.Run("unknown and empty kinds are invalid", func(t *testing.T) {
		t.Parallel()
		assert.False(t, TimelineKind("").Valid())
		assert.False(t, TimelineKind("future").Valid())
	})
	t.Run("typed fields retain JSON contract", func(t *testing.T) {
		t.Parallel()
		var event TimelineEvent
		require.NoError(t, json.Unmarshal([]byte(`{"kind":"decision","state":"banned","sourceKind":"manual"}`), &event))
		assert.Equal(t, TimelineDecision, event.Kind)
		assert.Equal(t, DecisionBanned, event.State)
		assert.Equal(t, SourceManual, event.SourceKind)
		encoded, err := json.Marshal(event)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"kind":"decision"`)
		assert.Contains(t, string(encoded), `"state":"banned"`)
		assert.Contains(t, string(encoded), `"sourceKind":"manual"`)
	})
}
