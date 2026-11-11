package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// sampleResult verifies that JSON and YAML use the same field names.
type sampleResult struct {
	// IP is the address written by the encoder.
	IP string `json:"ipAddress" yaml:"ipAddress"`
	// Reason is optional in either format.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("json uses json tags", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatJSON), &output)(sampleResult{IP: "203.0.113.10"}))

		var result map[string]any
		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		assert.Equal(t, "203.0.113.10", result["ipAddress"])
		assert.NotContains(t, result, "reason")
	})

	t.Run("yaml uses yaml tags directly", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(sampleResult{IP: "203.0.113.10"}))

		var result map[string]any
		require.NoError(t, yaml.Load(output.Bytes(), &result))
		assert.Equal(t, "203.0.113.10", result["ipAddress"])
		assert.NotContains(t, result, "reason")
		assert.NotContains(t, result, "ip")
	})

	t.Run("text is a yaml alias", func(t *testing.T) {
		t.Parallel()

		value := sampleResult{IP: "203.0.113.10", Reason: "Manual review"}
		var textOutput, yamlOutput bytes.Buffer
		require.NoError(t, New(ptr(FormatText), &textOutput)(value))
		require.NoError(t, New(ptr(FormatYAML), &yamlOutput)(value))
		assert.Equal(t, yamlOutput.String(), textOutput.String())
	})

	t.Run("uses the format selected after encoder creation", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		format := FormatYAML
		encode := New(&format, &output)
		format = FormatJSON

		require.NoError(t, encode(sampleResult{IP: "203.0.113.10"}))
		var result map[string]any
		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		assert.Equal(t, "203.0.113.10", result["ipAddress"])
	})

	t.Run("rejects nil format", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, New(nil, io.Discard)(sampleResult{}), "output format is not configured")
	})

	t.Run("rejects an unsupported format", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, New(ptr("xml"), io.Discard)(sampleResult{}), "unsupported output format")
	})

	for _, format := range []string{FormatJSON, FormatYAML, FormatText} {
		t.Run("propagates "+format+" write errors", func(t *testing.T) {
			t.Parallel()

			err := New(ptr(format), failingWriter{})(sampleResult{IP: "203.0.113.10"})
			require.ErrorContains(t, err, "write failed")
		})
	}
}

// failingWriter simulates a broken stdout stream.
type failingWriter struct{}

// Write always reports an output failure.
func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestYAMLIntegerPrecision(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	input := map[string]int64{"revision": 9007199254740993}

	require.NoError(t, New(ptr(FormatYAML), &output)(input))
	var decoded map[string]int64
	require.NoError(t, yaml.Load(output.Bytes(), &decoded))
	assert.Equal(t, input, decoded)
}

// ptr returns a pointer to a format for tests of the flag-bound encoder.
func ptr(format string) *string { return &format }

func TestBanRecordsYAML(t *testing.T) {
	t.Parallel()

	deadline := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

	t.Run("round trips decisions sources and acknowledgements", func(t *testing.T) {
		t.Parallel()

		records := []bans.Record{{
			Decision: decisions.Decision{
				ID:        "one",
				IP:        "203.0.113.10",
				State:     decisions.StateBanned,
				Revision:  4,
				ExpiresAt: deadline,
			},
			Sources: []bans.Source{
				{Kind: bans.SourceAutomatic, ExpiresAt: deadline},
				{
					Kind:      bans.SourceManual,
					ExpiresAt: deadline,
					Reason:    "Incident",
				},
			},
			Deliveries: []decisions.Acknowledgement{{Destination: "webhook.receiver", Revision: 4}},
		}}

		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(records))
		assert.Contains(t, output.String(), "ipAddress:")
		assert.Contains(t, output.String(), "acknowledgedRevision:")
		assert.NotContains(t, output.String(), "failures:")
		assert.Equal(t, 1, strings.Count(output.String(), "reason:"))

		var decoded []bans.Record
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded, 1)
		assert.Equal(t, records[0].Decision, decoded[0].Decision)
		assert.Equal(t, records[0].Sources, decoded[0].Sources)
		assert.Equal(t, records[0].Deliveries, decoded[0].Deliveries)
	})

	t.Run("includes released historical decisions", func(t *testing.T) {
		t.Parallel()

		records := []bans.Record{{Decision: decisions.Decision{ID: "released", State: decisions.StateUnbanned}}}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(records))
		var decoded []bans.Record
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded, 1)
		assert.Equal(t, decisions.StateUnbanned, decoded[0].Decision.State)
	})

	t.Run("preserves record order", func(t *testing.T) {
		t.Parallel()

		records := []bans.Record{{Decision: decisions.Decision{ID: "one"}}, {Decision: decisions.Decision{ID: "two"}}}
		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)(records))
		var decoded []bans.Record
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		require.Len(t, decoded, 2)
		assert.Equal(t, "one", decoded[0].Decision.ID)
		assert.Equal(t, "two", decoded[1].Decision.ID)
	})

	t.Run("empty records encode as empty sequence", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		require.NoError(t, New(ptr(FormatYAML), &output)([]bans.Record{}))
		var decoded []bans.Record
		require.NoError(t, yaml.Load(output.Bytes(), &decoded))
		assert.Empty(t, decoded)
	})
}

func TestSingleBanRecordYAML(t *testing.T) {
	t.Parallel()

	record := bans.Record{Decision: decisions.Decision{ID: "one", IP: "203.0.113.10"}}
	var output bytes.Buffer
	require.NoError(t, New(ptr(FormatYAML), &output)(record))
	var decoded bans.Record
	require.NoError(t, yaml.Load(output.Bytes(), &decoded))
	assert.Equal(t, record.Decision, decoded.Decision)
	assert.NotContains(t, output.String(), "- decision:")
}
