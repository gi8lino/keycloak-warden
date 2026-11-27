package model_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

func TestDecisionStateSerialization(t *testing.T) {
	t.Parallel()

	t.Run("banned JSON", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(model.Decision{State: model.DecisionBanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"state":"banned"`)

		var decoded model.Decision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DecisionBanned, decoded.State)
	})

	t.Run("unbanned JSON", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(model.Decision{State: model.DecisionUnbanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"state":"unbanned"`)

		var decoded model.Decision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DecisionUnbanned, decoded.State)
	})

	t.Run("banned YAML", func(t *testing.T) {
		t.Parallel()

		encoded, err := yaml.Marshal(model.Decision{State: model.DecisionBanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "state: banned")

		var decoded model.Decision
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DecisionBanned, decoded.State)
	})

	t.Run("unbanned YAML", func(t *testing.T) {
		t.Parallel()

		encoded, err := yaml.Marshal(model.Decision{State: model.DecisionUnbanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "state: unbanned")

		var decoded model.Decision
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DecisionUnbanned, decoded.State)
	})
}

func TestDeliveryDesiredStateSerialization(t *testing.T) {
	t.Parallel()

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(model.Delivery{DesiredState: model.DecisionBanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"desiredState":"banned"`)

		var decoded model.Delivery
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DecisionBanned, decoded.DesiredState)
	})

	t.Run("YAML", func(t *testing.T) {
		t.Parallel()

		encoded, err := yaml.Marshal(model.Delivery{DesiredState: model.DecisionUnbanned})
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "desiredState: unbanned")

		var decoded model.Delivery
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DecisionUnbanned, decoded.DesiredState)
	})
}

func TestDeliveryStatusSerialization(t *testing.T) {
	t.Parallel()

	t.Run("JSON status and outcome", func(t *testing.T) {
		t.Parallel()
		input := model.Delivery{
			Status:   model.DeliveryRetrying,
			Attempts: []model.DeliveryAttempt{{Outcome: model.AttemptFailed}},
		}
		encoded, err := json.Marshal(input)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"status":"retrying"`)
		assert.Contains(t, string(encoded), `"outcome":"failed"`)

		var decoded model.Delivery
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DeliveryRetrying, decoded.Status)
		require.Len(t, decoded.Attempts, 1)
		assert.Equal(t, model.AttemptFailed, decoded.Attempts[0].Outcome)
	})

	t.Run("YAML status and outcome", func(t *testing.T) {
		t.Parallel()
		input := model.Delivery{
			Status:   model.DeliveryDelivered,
			Attempts: []model.DeliveryAttempt{{Outcome: model.AttemptSucceeded}},
		}
		encoded, err := yaml.Marshal(input)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "status: delivered")
		assert.Contains(t, string(encoded), "outcome: succeeded")

		var decoded model.Delivery
		require.NoError(t, yaml.Unmarshal(encoded, &decoded))
		assert.Equal(t, model.DeliveryDelivered, decoded.Status)
		require.Len(t, decoded.Attempts, 1)
		assert.Equal(t, model.AttemptSucceeded, decoded.Attempts[0].Outcome)
	})
}
