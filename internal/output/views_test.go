package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestRecordsYAML(t *testing.T) {
	t.Parallel()
	deadline := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

	t.Run("round trips decisions sources and acknowledgements", func(t *testing.T) {
		t.Parallel()
		records := Records{{
			Decision: decisions.Decision{ID: "one", IP: "203.0.113.10", State: decisions.StateBanned, Revision: 4, ExpiresAt: deadline},
			Sources: []bans.Source{
				{Kind: bans.SourceAutomatic, ExpiresAt: deadline},
				{Kind: bans.SourceManual, ExpiresAt: deadline, Reason: "Incident"},
			},
			Deliveries: []decisions.Acknowledgement{{Destination: "webhook.receiver", Revision: 4}},
		}}

		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(records))
		assert.Contains(t, output.String(), "ipAddress:")
		assert.Contains(t, output.String(), "acknowledgedRevision:")
		assert.NotContains(t, output.String(), "failures:")
		assert.Equal(t, 1, strings.Count(output.String(), "reason:"))

		var decoded Records
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded, 1)
		assert.Equal(t, records[0].Decision, decoded[0].Decision)
		assert.Equal(t, records[0].Sources, decoded[0].Sources)
		assert.Equal(t, records[0].Deliveries, decoded[0].Deliveries)
	})

	t.Run("includes released historical decisions", func(t *testing.T) {
		t.Parallel()
		records := Records{{Decision: decisions.Decision{ID: "released", State: decisions.StateUnbanned}}}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(records))
		var decoded Records
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded, 1)
		assert.Equal(t, decisions.StateUnbanned, decoded[0].Decision.State)
	})

	t.Run("preserves record order", func(t *testing.T) {
		t.Parallel()
		records := Records{{Decision: decisions.Decision{ID: "one"}}, {Decision: decisions.Decision{ID: "two"}}}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(records))
		var decoded Records
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded, 2)
		assert.Equal(t, "one", decoded[0].Decision.ID)
		assert.Equal(t, "two", decoded[1].Decision.ID)
	})

	t.Run("empty records encode as empty sequence", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(Records{}))
		var decoded Records
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		assert.Empty(t, decoded)
	})
}
