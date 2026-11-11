package adminclient_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/adminclient"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("accepts loopback HTTP with a token", func(t *testing.T) {
		t.Parallel()

		client, err := adminclient.New("http://127.0.0.1:8081", "secret")

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("rejects remote unencrypted HTTP", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("http://example.com:8081", "admin")

		require.Error(t, err)
	})

	t.Run("rejects URL credentials", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("http://user:pass@localhost:8081", "admin")

		require.Error(t, err)
	})

	t.Run("rejects unsupported schemes", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("ftp://localhost", "admin")

		require.Error(t, err)
	})

	t.Run("accepts application route prefix", func(t *testing.T) {
		t.Parallel()

		client, err := adminclient.New("http://localhost:8081/warden", "admin")

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("rejects query parameters", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("https://localhost?debug=1", "admin")

		require.Error(t, err)
	})

	t.Run("requires admin token", func(t *testing.T) {
		t.Parallel()

		_, err := adminclient.New("http://localhost:8081", "")

		require.ErrorContains(t, err, "admin-token")
	})
}

func TestValidateURL(t *testing.T) {
	t.Parallel()

	t.Run("accepts remote HTTPS", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, adminclient.ValidateURL("https://warden.example.com:8443"))
	})

	t.Run("accepts local HTTP", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, adminclient.ValidateURL("http://127.0.0.1:8081"))
	})

	t.Run("rejects remote HTTP", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("http://warden:8081"), "HTTPS")
	})

	t.Run("accepts prefixed application URL", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, adminclient.ValidateURL("https://warden.example.com/warden"))
	})

	t.Run("rejects path traversal in route prefix", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://warden.example.com/warden/../bans"), "route prefix")
	})

	t.Run("rejects encoded route prefix", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://warden.example.com/ward%65n"), "application-url")
	})

	t.Run("rejects credentials", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://user:password@warden.example.com"), "application-url")
	})

	t.Run("rejects trailing question mark", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https://warden.example.com?"), "application-url")
	})

	t.Run("rejects unsupported scheme", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("ftp://warden.example.com"), "HTTPS")
	})

	t.Run("rejects missing host", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, adminclient.ValidateURL("https:///"), "application-url")
	})
}
