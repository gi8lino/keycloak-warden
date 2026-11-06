package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	t.Run("prints headers and pretty JSON body", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		request := httptest.NewRequest(
			http.MethodPost,
			"/webhook",
			strings.NewReader(`{"ipAddress":"203.0.113.10","active":true}`),
		)
		request.Header.Set("X-Warden-Timestamp", "12345")

		response := httptest.NewRecorder()
		handler(&output).ServeHTTP(response, request)

		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", response.Code)
		}
		for _, expected := range []string{
			"Webhook #1", "POST /webhook", "X-Warden-Timestamp: 12345",
			`"ipAddress": "203.0.113.10"`, `"active": true`,
		} {
			if !strings.Contains(output.String(), expected) {
				t.Errorf("output does not contain %q: %s", expected, output.String())
			}
		}
	})

	t.Run("rejects oversized bodies without logging", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		request := httptest.NewRequest(
			http.MethodPost,
			"/webhook",
			strings.NewReader(strings.Repeat("x", maxBodyBytes+1)),
		)
		response := httptest.NewRecorder()
		handler(&output).ServeHTTP(response, request)

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", response.Code)
		}
		if output.Len() != 0 {
			t.Fatal("oversized request was logged")
		}
	})

	t.Run("responds to health checks", func(t *testing.T) {
		t.Parallel()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		handler(&bytes.Buffer{}).ServeHTTP(response, request)

		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", response.Code)
		}
	})
}
