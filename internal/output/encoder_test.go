package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// fakePrintable supplies a text representation independent of JSON formatting.
type fakePrintable struct {
	// Name supplies the sample address rendered by the test result.
	Name string `json:"ipAddress"`
}

// WriteText prints a dedicated human-readable representation.
func (p fakePrintable) WriteText(w io.Writer) error {
	_, err := io.WriteString(w, "IP: "+p.Name+"\n")
	return err
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("text uses the result's text renderer", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer

		require.NoError(t, New(ptr(FormatText), &output)(fakePrintable{Name: "203.0.113.10"}))
		assert.Equal(t, "IP: 203.0.113.10\n", output.String())
	})

	t.Run("json preserves exported field names", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer

		require.NoError(t, New(ptr(FormatJSON), &output)(fakePrintable{Name: "203.0.113.10"}))
		var result map[string]any

		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		assert.Equal(t, "203.0.113.10", result["ipAddress"])
	})

	t.Run("yaml uses json field names", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer

		require.NoError(t, New(ptr(FormatYAML), &output)(fakePrintable{Name: "203.0.113.10"}))
		var result map[string]any

		require.NoError(t, yaml.Unmarshal(output.Bytes(), &result))
		assert.Equal(t, "203.0.113.10", result["ipAddress"])
	})

	t.Run("uses the format selected after encoder creation", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		format := FormatText
		encode := New(&format, &output)
		format = FormatJSON

		require.NoError(t, encode(fakePrintable{Name: "203.0.113.10"}))
		var result map[string]any

		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		assert.Equal(t, "203.0.113.10", result["ipAddress"])
	})

	t.Run("rejects an unsupported format", func(t *testing.T) {
		t.Parallel()

		err := New(ptr("xml"), io.Discard)(fakePrintable{})

		require.ErrorContains(t, err, "unsupported output format")
	})

	t.Run("rejects values without a text renderer", func(t *testing.T) {
		t.Parallel()

		err := New(ptr(FormatText), io.Discard)(struct{}{})

		require.ErrorContains(t, err, "text output is not supported")
	})

	t.Run("propagates text write errors", func(t *testing.T) {
		t.Parallel()

		err := New(ptr(FormatText), failingWriter{})(fakePrintable{Name: "203.0.113.10"})

		require.ErrorContains(t, err, "write failed")
	})
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

	require.NoError(t, yaml.Unmarshal(output.Bytes(), &decoded))
	assert.Equal(t, input, decoded)
}

// ptr returns a pointer to a format for tests of the flag-bound encoder.
func ptr(format string) *string { return &format }
