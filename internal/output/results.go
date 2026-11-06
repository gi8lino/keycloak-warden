package output

import (
	"fmt"
	"io"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
)

// Item describes the outcome of one requested IP operation.
type Item struct {
	// IPAddress is the canonical IP on which the operation was attempted.
	IPAddress string `json:"ipAddress"`
	// Success reports whether the API accepted the operation.
	Success bool `json:"success"`
	// Ban is the returned decision and source view when successful.
	Ban *bans.Ban `json:"ban,omitempty"`
	// Error is the per-address error when unsuccessful.
	Error string `json:"error,omitempty"`
}

// Batch is a complete response for a multi-IP administrative command.
type Batch struct {
	// Operation identifies whether this batch is a ban or unban request.
	Operation string `json:"operation"`
	// Results contains one record per canonical requested address.
	Results []Item `json:"results"`
	// Succeeded counts successful operations.
	Succeeded int `json:"succeeded"`
	// Failed counts individual IP operations that failed.
	Failed int `json:"failed"`
}

// WriteText renders successful operations and an aggregate summary.
// Individual errors are also returned to the CLI for stderr reporting.
func (batch Batch) WriteText(w io.Writer) error {
	verb := "Banned"
	if batch.Operation == "unban" {
		verb = "Unbanned"
	}
	for _, item := range batch.Results {
		if !item.Success {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", verb, item.IPAddress); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%d succeeded, %d failed\n", batch.Succeeded, batch.Failed)
	return err
}
