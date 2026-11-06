// Package response writes shared HTTP response formats used across transport layers.
package response

import (
	"net/http"

	httpkitresponse "github.com/containeroo/httpkit/response"
)

// Respond writes a JSON response with the supplied status code.
func Respond(w http.ResponseWriter, status int, value any) {
	httpkitresponse.WriteJSON(w, status, value)
}

// Problem writes a consistent JSON error response.
func Problem(w http.ResponseWriter, status int, message string) {
	Respond(w, status, map[string]any{
		"error":    message,
		"problems": map[string]string{},
	})
}
