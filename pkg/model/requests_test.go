package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestJSON(t *testing.T) {
	t.Parallel()

	t.Run("manual ban duration is a string", func(t *testing.T) {
		t.Parallel()

		request := CreateBanRequest{
			IP:       "203.0.113.42",
			Duration: "15m0s",
			Reason:   "Investigation",
		}

		encoded, err := json.Marshal(request)
		require.NoError(t, err)
		assert.JSONEq(t, `{"ipAddress":"203.0.113.42","duration":"15m0s","reason":"Investigation"}`, string(encoded))

		var decoded CreateBanRequest
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, request, decoded)
	})

	t.Run("explicit delivery retry", func(t *testing.T) {
		t.Parallel()

		request := RetryRequest{
			DecisionID:  "decision-one",
			Revision:    3,
			Destination: "webhook.receiver",
			Actor:       "operator",
		}

		encoded, err := json.Marshal(request)
		require.NoError(t, err)
		assert.JSONEq(t, `{"decisionId":"decision-one","revision":3,"destination":"webhook.receiver","actor":"operator"}`, string(encoded))

		var decoded RetryRequest
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, request, decoded)
	})

	t.Run("queued retry response", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(RetryResponse{Queued: true})
		require.NoError(t, err)
		assert.JSONEq(t, `{"queued":true}`, string(encoded))
	})
}
