package client

import (
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestOptions(t *testing.T) {
	t.Parallel()
	t.Run("ordinary timeout override reaches request", func(t *testing.T) {
		t.Parallel()
		c := deadlineClient(t, time.Second, 2*time.Second, WithRequestTimeout(2*time.Second))
		_, err := c.List(t.Context())
		require.NoError(t, err)
	})
	t.Run("maintenance timeout is independent", func(t *testing.T) {
		t.Parallel()
		c := deadlineClient(t, 3*time.Second, 4*time.Second, WithRequestTimeout(time.Second), WithMaintenanceTimeout(4*time.Second))
		_, err := c.PruneObservations(t.Context())
		require.NoError(t, err)
	})
	t.Run("caller deadline takes precedence", func(t *testing.T) {
		t.Parallel()
		c := deadlineClient(t, time.Second, 2*time.Second, WithRequestTimeout(time.Minute))
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		_, err := c.List(ctx)
		require.NoError(t, err)
	})
	t.Run("response at configured limit is accepted", func(t *testing.T) {
		t.Parallel()
		c := responseLimitClient(t, "[]")
		_, err := c.List(t.Context())
		require.NoError(t, err)
	})
	t.Run("response exceeding configured limit is rejected", func(t *testing.T) {
		t.Parallel()
		c := responseLimitClient(t, "[] ")
		_, err := c.List(t.Context())
		require.ErrorContains(t, err, "exceeds 2 bytes")
	})
	t.Run("zero request timeout is rejected", func(t *testing.T) {
		t.Parallel()
		assertRejectedOption(t, WithRequestTimeout(0))
	})
	t.Run("negative request timeout is rejected", func(t *testing.T) {
		t.Parallel()
		assertRejectedOption(t, WithRequestTimeout(-time.Second))
	})
	t.Run("zero maintenance timeout is rejected", func(t *testing.T) {
		t.Parallel()
		assertRejectedOption(t, WithMaintenanceTimeout(0))
	})
	t.Run("negative maintenance timeout is rejected", func(t *testing.T) {
		t.Parallel()
		assertRejectedOption(t, WithMaintenanceTimeout(-time.Second))
	})
	t.Run("zero response limit is rejected", func(t *testing.T) {
		t.Parallel()
		assertRejectedOption(t, WithMaxResponseBytes(0))
	})
	t.Run("negative response limit is rejected", func(t *testing.T) {
		t.Parallel()
		assertRejectedOption(t, WithMaxResponseBytes(-1))
	})
	t.Run("overflowing response limit is rejected on 64 bit platforms", func(t *testing.T) {
		t.Parallel()
		if int64(math.MaxInt) != math.MaxInt64 {
			t.Skip("int cannot represent MaxInt64")
		}
		assertRejectedOption(t, WithMaxResponseBytes(math.MaxInt))
	})
	t.Run("options are applied once with last override winning", func(t *testing.T) {
		t.Parallel()
		calls := 0
		c, err := New("http://localhost", "secret", nil, WithRequestTimeout(time.Second), func(o *clientOptions) {
			calls++
			o.clientTimeout = 2 * time.Second
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
		assert.Equal(t, 2*time.Second, c.options.clientTimeout)
	})
}

// assertRejectedOption verifies invalid settings fail before any client can send requests.
func assertRejectedOption(t *testing.T, option Option) {
	t.Helper()
	c, err := New("http://localhost", "secret", option)
	require.Error(t, err)
	assert.Nil(t, c)
}

// deadlineClient checks the deadline on requests produced by the configured client.
func deadlineClient(t *testing.T, minimum, maximum time.Duration, options ...Option) *Client {
	t.Helper()
	c, err := New("http://localhost", "secret", options...)
	require.NoError(t, err)
	c.http.Transport = maintenanceTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		require.True(t, ok)
		remaining := time.Until(deadline)
		assert.Greater(t, remaining, minimum)
		assert.LessOrEqual(t, remaining, maximum)
		body := "{}"
		if r.URL.Path == "/bans" {
			body = "[]"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})
	return c
}

// responseLimitClient provides a bounded response without depending on network timing.
func responseLimitClient(t *testing.T, body string) *Client {
	t.Helper()
	c, err := New("http://localhost", "secret", WithMaxResponseBytes(2))
	require.NoError(t, err)
	c.http.Transport = maintenanceTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})
	return c
}
