package output

import (
	"github.com/gi8lino/keycloak-warden/pkg/client"
)

// Item describes the outcome of one requested IP operation.
type Item struct {
	// IPAddress is the canonical IP on which the operation was attempted.
	IPAddress string `json:"ipAddress" yaml:"ipAddress"`
	// Success reports whether the API accepted the operation.
	Success bool `json:"success" yaml:"success"`
	// Ban is the returned decision record and sources when successful.
	Ban *client.Record `json:"ban,omitempty" yaml:"ban,omitempty"`
	// Error is the per-address error when unsuccessful.
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}

// Batch is a complete response for a multi-IP administrative command.
type Batch struct {
	// Operation identifies whether this batch is a ban or unban request.
	Operation string `json:"operation" yaml:"operation"`
	// Results contains one record per canonical requested address.
	Results []Item `json:"results" yaml:"results"`
	// Succeeded counts successful operations.
	Succeeded int `json:"succeeded" yaml:"succeeded"`
	// Failed counts individual IP operations that failed.
	Failed int `json:"failed" yaml:"failed"`
}
