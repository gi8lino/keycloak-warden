package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestBatchYAML(t *testing.T) {
	t.Parallel()

	t.Run("includes successes and failures in a single document", func(t *testing.T) {
		t.Parallel()
		batch := Batch{Operation: "ban", Results: []Item{
			{IPAddress: "203.0.113.10", Success: true},
			{IPAddress: "203.0.113.20", Error: "rejected"},
		}, Succeeded: 1, Failed: 1}

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
		batch := Batch{Operation: "ban", Results: []Item{{
			IPAddress: "203.0.113.10",
			Success:   true,
			Ban: &bans.Record{
				Decision:   decisions.Decision{ID: "decision-one", IP: "203.0.113.10", Revision: 4},
				Deliveries: []decisions.Acknowledgement{{Destination: "webhook.receiver", Revision: 4}},
			},
		}}, Succeeded: 1}
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
		batch := Batch{Operation: "unban", Results: []Item{{IPAddress: "203.0.113.10", Success: true}}, Succeeded: 1}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(batch))
		assert.NotContains(t, output.String(), "ban:")
		assert.NotContains(t, output.String(), "error:")
		var result Batch
		require.NoError(t, yaml.Load(output.Bytes(), &result))
		assert.Equal(t, batch, result)
	})
}
