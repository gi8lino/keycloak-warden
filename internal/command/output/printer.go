package output

import (
	"fmt"
	"io"
)

// NewPrinter selects concise mutation results, explicit structured output, or quiet mode.
func NewPrinter(format *string, quiet *bool, writer io.Writer) Encoder {
	return func(value any) error {
		if *quiet {
			return nil
		}

		if *format != "" {
			return encode(format, writer, value)
		}

		// Ban/unban batches use concise confirmations; other results fall back to YAML.
		if batch, ok := value.(Batch); ok {
			return writeConfirmation(writer, batch)
		}

		fallback := FormatYAML
		return encode(&fallback, writer, value)
	}
}

// writeConfirmation prints accepted operations; command errors are reported separately on stderr.
func writeConfirmation(writer io.Writer, batch Batch) error {
	var verb string
	switch batch.Operation {
	case OperationBan:
		verb = "Banned"
	case OperationUnban:
		verb = "Unbanned"
	default:
		return fmt.Errorf("unsupported operation %q", batch.Operation)
	}

	for _, item := range batch.Results {
		if !item.Success {
			continue
		}
		if _, err := fmt.Fprintf(writer, "%s %s\n", verb, item.IPAddress); err != nil {
			return err
		}
	}
	return nil
}
