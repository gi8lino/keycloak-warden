package output

import (
	"fmt"
	"io"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// Bans is a list of active ban views including automatic and manual sources.
type Bans []bans.Ban

// WriteText displays each effective ban and its active source details.
func (list Bans) WriteText(w io.Writer) error {
	if len(list) == 0 {
		_, err := fmt.Fprintln(w, "No active bans")
		return err
	}
	for _, item := range list {
		if _, err := fmt.Fprintf(
			w,
			"%s  expires %s  failures %d\n",
			item.Decision.IP,
			item.Decision.ExpiresAt.Format(time.RFC3339),
			item.Decision.Failures,
		); err != nil {
			return err
		}
		for _, source := range item.Sources {
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
	return nil
}

// Inspection is a persisted decision with its delivery acknowledgements.
type Inspection decisions.Inspection

// WriteText displays the inspected decision and delivery status.
func (view Inspection) WriteText(w io.Writer) error {
	state := "inactive"
	if view.Decision.Active {
		state = "active"
	}

	if _, err := fmt.Fprintf(w, "ID: %s\nIP: %s\nState: %s\nRevision: %d\nExpires: %s\nFailures: %d\n",
		view.Decision.ID, view.Decision.IP, state, view.Decision.Revision,
		view.Decision.ExpiresAt.Format(time.RFC3339), view.Decision.Failures); err != nil {
		return err
	}

	if len(view.Deliveries) == 0 {
		_, err := fmt.Fprintln(w, "Deliveries: none")
		return err
	}

	if _, err := fmt.Fprintln(w, "Deliveries:"); err != nil {
		return err
	}

	for _, delivery := range view.Deliveries {
		if _, err := fmt.Fprintf(w, "  %s: revision %d\n", delivery.Destination, delivery.Revision); err != nil {
			return err
		}
	}
	return nil
}

// Inspections is an ordered collection of persisted decision views.
type Inspections []decisions.Inspection

// WriteText displays each decision separated by a blank line.
func (views Inspections) WriteText(w io.Writer) error {
	for i, view := range views {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if err := (Inspection(view)).WriteText(w); err != nil {
			return err
		}
	}
	return nil
}
