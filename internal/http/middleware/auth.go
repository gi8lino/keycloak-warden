// Package middleware implements HTTP request security independently of application logic.
package middleware

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
	"github.com/gi8lino/keycloak-warden/internal/signing"
)

const (
	// maxEventBodyBytes limits signed Snitch event bodies to 64 KiB.
	maxEventBodyBytes = 64 << 10

	// requestReadTimeout bounds how long the server waits to read a signed event body.
	requestReadTimeout = 5 * time.Second
)

// AuthenticateSnitch verifies signed event bodies without trusting forwarding headers.
func AuthenticateSnitch(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				httpresponse.Problem(w, http.StatusUnsupportedMediaType, "Expected application/json.")
				return
			}

			controller := http.NewResponseController(w)
			if err := controller.SetReadDeadline(time.Now().Add(requestReadTimeout)); err == nil {
				defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
			}

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventBodyBytes))
			if err != nil {
				var limit *http.MaxBytesError
				if errors.As(err, &limit) {
					httpresponse.Problem(w, http.StatusRequestEntityTooLarge, "Event body is too large.")
					return
				}
				httpresponse.Problem(w, http.StatusBadRequest, "Invalid request body.")
				return
			}

			ts := r.Header.Get("X-Snitch-Timestamp")
			sig := r.Header.Get("X-Snitch-Signature")
			if !signing.Valid(secret, ts, sig, body, time.Now()) {
				httpresponse.Problem(w, http.StatusUnauthorized, "Invalid webhook authentication.")
				return
			}

			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}
