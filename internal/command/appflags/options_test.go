package appflags

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/containeroo/tinyflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/pkg/client"
)

func TestClientOptions(t *testing.T) {
	t.Parallel()

	t.Run("passes configured response limits to HTTP client", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/bans", r.URL.Path)
			_, _ = io.WriteString(w, "[] ")
		}))
		t.Cleanup(server.Close)

		root := tinyflags.NewCommand("warden", tinyflags.ContinueOnError)
		serverFlags := RegisterServer(root)
		flags := RegisterAdmin(root.Command("list-active", "List bans"), serverFlags)

		require.NoError(t, root.Parse([]string{
			"list-active",
			"--application-url=" + server.URL,
			"--admin-token=secret",
			"--request-timeout=2s",
			"--maintenance-timeout=1m",
			"--max-response-bytes=2",
		}))

		api, err := client.New(*flags.ApplicationURL, *flags.AdminToken, flags.ClientOptions()...)
		require.NoError(t, err)

		_, err = api.List(t.Context())
		require.ErrorContains(t, err, "application response exceeds 2 bytes")
	})
}
