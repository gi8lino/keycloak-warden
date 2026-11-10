package output

import (
	"fmt"
	"io"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// Records is a collection of decisions with active sources and delivery acknowledgements.
type Records []bans.Record

// WriteText writes records separated by a blank line.
func (records Records) WriteText(w io.Writer) error {
	for _, record := range records {
		if err := writeRecord(w, record); err != nil {
			return err
		}
	}

	return nil
}

// writeRecord displays the same decision, source, and delivery fields as JSON output.
func writeRecord(w io.Writer, record bans.Record) error {
	decision := record.Decision
	if _, err := fmt.Fprintf(w, "ID: %s\nIP: %s\nState: %s\nRevision: %d\nExpires: %s\n",
		decision.ID, decision.IP, decision.State, decision.Revision,
		decision.ExpiresAt.Format(time.RFC3339)); err != nil {
		return err
	}

	if len(record.Sources) == 0 {
		if _, err := fmt.Fprintln(w, "Sources: none"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "Sources:"); err != nil {
			return err
		}
		for _, source := range record.Sources {
			if _, err := fmt.Fprintf(w, "  %s: expires %s", source.Kind, source.ExpiresAt.Format(time.RFC3339)); err != nil {
				return err
			}
			if source.Reason != "" {
				if _, err := fmt.Fprintf(w, " (%q)", source.Reason); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
	}

	if len(record.Deliveries) == 0 {
		_, err := fmt.Fprintln(w, "Deliveries: none")
		return err
	}
	if _, err := fmt.Fprintln(w, "Deliveries:"); err != nil {
		return err
	}
	for _, delivery := range record.Deliveries {
		if _, err := fmt.Fprintf(w, "  %s: revision %d\n", delivery.Destination, delivery.Revision); err != nil {
			return err
		}
	}
	return nil
}
