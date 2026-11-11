// Package output encodes command results in JSON or YAML.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v4"
)

const (
	// FormatText is a compatibility alias for human-readable YAML output.
	FormatText = "text"
	// FormatJSON renders a single JSON document.
	FormatJSON = "json"
	// FormatYAML renders a single YAML document.
	FormatYAML = "yaml"
)

// Encoder serializes one complete command result to the selected destination.
type Encoder func(any) error

// New creates an encoder that reads the selected output format at write time.
func New(format *string, writer io.Writer) Encoder {
	return func(value any) error {
		if format == nil {
			return errors.New("output format is not configured")
		}

		switch *format {
		case FormatJSON:
			return json.NewEncoder(writer).Encode(value)
		case FormatText, FormatYAML:
			encoder := yaml.NewEncoder(writer)
			if err := encoder.Encode(value); err != nil {
				return err
			}
			return encoder.Close()
		default:
			return fmt.Errorf("unsupported output format %q", *format)
		}
	}
}
