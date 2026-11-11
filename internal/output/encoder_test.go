package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
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
