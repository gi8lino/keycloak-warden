package client

import "fmt"

// Error identifies a non-2xx administrative API response.
type Error struct {
	// Code is the upstream HTTP status code.
	Code int
	// Message is an optional bounded server-supplied explanation.
	Message string
}

// Error describes an unsuccessful request without exposing the bearer token.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("application HTTP %d", e.Code)
	}
	return fmt.Sprintf("application HTTP %d: %s", e.Code, e.Message)
}
