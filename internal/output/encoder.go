// Package output encodes command results in text, JSON, or YAML.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

const (
	// FormatText renders human-readable command output.
	FormatText = "text"
	// FormatJSON renders a single JSON document.
	FormatJSON = "json"
	// FormatYAML renders a single YAML document.
	FormatYAML = "yaml"
)

// Encoder serializes one complete command result to the selected destination.
type Encoder func(any) error

// TextWriter is implemented by command results that support a human-readable representation.
type TextWriter interface {
	WriteText(io.Writer) error
}

// New creates an encoder that reads the output format when the result is written.
// This allows CLI flags to be parsed after command registration.
func New(format *string, writer io.Writer) Encoder {
	return func(value any) error {
		if format == nil {
			return errors.New("output format is not configured")
		}

		switch *format {
		case FormatText:
			printable, ok := value.(TextWriter)
			if !ok {
				return fmt.Errorf("text output is not supported for %T", value)
			}
			return printable.WriteText(writer)
		case FormatJSON:
			return json.NewEncoder(writer).Encode(value)
		case FormatYAML:
			// Marshal through JSON to honor existing json field tags,
			// including ipAddress, expiresAt, and omitted fields.
			data, err := json.Marshal(value)
			if err != nil {
				return err
			}
			var normalized yaml.Node
			if err := yaml.Unmarshal(data, &normalized); err != nil {
				return err
			}
			return yaml.NewEncoder(writer).Encode(&normalized)
		default:
			return fmt.Errorf("unsupported output format %q", *format)
		}
	}
}
