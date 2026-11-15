package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestBatchYAML(t *testing.T) {
	t.Parallel()

	t.Run("includes successes and failures in a single document", func(t *testing.T) {
		t.Parallel()

		batch := Batch{
			Operation: OperationBan,
			Results: []Item{
				{IPAddress: "203.0.113.10", Success: true},
				{IPAddress: "203.0.113.20", Error: "rejected"},
			},
			Succeeded: 1,
			Failed:    1,
		}

		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(batch))
		assert.Contains(t, output.String(), "ipAddress:")
		assert.NotContains(t, output.String(), "ipaddress:")
		var result Batch
		require.NoError(t, yaml.Load(output.Bytes(), &result))
		assert.Equal(t, batch, result)
	})

	t.Run("preserves nested ban response field names", func(t *testing.T) {
		t.Parallel()

		batch := Batch{
			Operation: OperationBan,
			Results: []Item{{
				IPAddress: "203.0.113.10",
				Success:   true,
				Ban: &client.Record{
					Decision: client.Decision{
						ID:       "decision-one",
						IP:       "203.0.113.10",
						Revision: 4,
					},
					Deliveries: []client.Acknowledgement{{Destination: "webhook.receiver", Revision: 4}},
				},
			}},
			Succeeded: 1,
		}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(batch))
		assert.Contains(t, output.String(), "ipAddress:")
		assert.Contains(t, output.String(), "acknowledgedRevision:")
		var decoded Batch
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded.Results, 1)
		require.NotNil(t, decoded.Results[0].Ban)
		assert.Equal(t, "203.0.113.10", decoded.Results[0].Ban.Decision.IP)
		assert.Equal(t, int64(4), decoded.Results[0].Ban.Deliveries[0].Revision)
	})

	t.Run("omits empty optional fields", func(t *testing.T) {
		t.Parallel()

		batch := Batch{
			Operation: OperationUnban,
			Results:   []Item{{IPAddress: "203.0.113.10", Success: true}},
			Succeeded: 1,
		}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(batch))
		assert.NotContains(t, output.String(), "ban:")
		assert.NotContains(t, output.String(), "error:")
		var result Batch
		require.NoError(t, yaml.Load(output.Bytes(), &result))
		assert.Equal(t, batch, result)
	})
}

func TestOperationJSON(t *testing.T) {
	t.Parallel()

	t.Run("ban uses the existing wire value", func(t *testing.T) {
		t.Parallel()

		var encoded bytes.Buffer
		err := New(ptr(FormatJSON), &encoded)(Batch{Operation: OperationBan})

		require.NoError(t, err)
		assert.Contains(t, encoded.String(), `"operation": "ban"`)

		var decoded Batch
		require.NoError(t, json.Unmarshal(encoded.Bytes(), &decoded))
		assert.Equal(t, OperationBan, decoded.Operation)
	})

	t.Run("unban uses the existing wire value", func(t *testing.T) {
		t.Parallel()

		var encoded bytes.Buffer
		err := New(ptr(FormatJSON), &encoded)(Batch{Operation: OperationUnban})

		require.NoError(t, err)
		assert.Contains(t, encoded.String(), `"operation": "unban"`)

		var decoded Batch
		require.NoError(t, json.Unmarshal(encoded.Bytes(), &decoded))
		assert.Equal(t, OperationUnban, decoded.Operation)
	})
}
