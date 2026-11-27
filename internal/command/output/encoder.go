// Package output formats command results for interactive and structured output.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v4"
)

const (
	// FormatJSON renders a single JSON document.
	FormatJSON = "json"
	// FormatYAML renders a single YAML document.
	FormatYAML = "yaml"
)

// Encoder serializes one complete command result to the selected destination.
type Encoder func(any) error

// New creates an encoder that reads the selected output format at write time.
func New(format *string, writer io.Writer, opts ...yaml.Option) Encoder {
	return func(value any) error { return encode(format, writer, value) }
}

// encode serializes one value in the output format selected at write time.
func encode(format *string, writer io.Writer, value any) error {
	if format == nil {
		return errors.New("output format is not configured")
	}

	switch *format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)

	case FormatYAML:
		dumper, err := yaml.NewDumper(
			writer,
			yaml.WithIndent(2),
			yaml.WithCompactSeqIndent(false))
		if err != nil {
			return err
		}
		if err := dumper.Dump(value); err != nil {
			return err
		}
		return dumper.Close()
	default:
		return fmt.Errorf("unsupported output format %q", *format)
	}
}
