package endpoint

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// maxAdminBodyBytes limits administrative JSON requests to 16 KiB.
const maxAdminBodyBytes = 16 << 10

// decodeAdminPayload enforces the common bounded, strict administrative JSON contract.
func decodeAdminPayload(w http.ResponseWriter, r *http.Request, target any, invalidMessage, largeMessage string) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		httpresponse.Problem(w, http.StatusUnsupportedMediaType, "Expected application/json.")
		return false
	}

	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
		defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAdminDecodeError(w, err, invalidMessage, largeMessage)
		return false
	}

	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeAdminDecodeError(w, err, "Expected exactly one JSON object.", largeMessage)
		return false
	}

	return true
}

// writeAdminDecodeError distinguishes oversized bodies from malformed JSON without leaking input.
func writeAdminDecodeError(w http.ResponseWriter, err error, invalidMessage, largeMessage string) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		httpresponse.Problem(w, http.StatusRequestEntityTooLarge, largeMessage)
		return
	}
	httpresponse.Problem(w, http.StatusBadRequest, invalidMessage)
}
