package response_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/http/response"
)

func TestRespond(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	response.Respond(w, http.StatusCreated, map[string]string{"decision": "created"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "created", body["decision"])
}

func TestProblem(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	response.Problem(w, http.StatusForbidden, "Denied.")

	assert.Equal(t, http.StatusForbidden, w.Code)
	var body struct {
		Error    string            `json:"error"`
		Problems map[string]string `json:"problems"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Denied.", body.Error)
	assert.NotNil(t, body.Problems)
	assert.Empty(t, body.Problems)
}
