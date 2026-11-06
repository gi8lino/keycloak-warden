package signing

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignature(t *testing.T) {
	t.Parallel()

	t.Run("known Snitch signature vector", func(t *testing.T) {
		t.Parallel()

		assert.Equal(
			t,
			"v1=9d713ed406bb7076d4123f0dc2c39d2df5c654ed4b0cd56b52c8b4c940bd63ae",
			Signature("key", "1700000000", []byte("{}")),
		)
	})

	t.Run("different bodies have different signatures", func(t *testing.T) {
		t.Parallel()

		assert.NotEqual(t, Signature("key", "1700000000", []byte("one")), Signature("key", "1700000000", []byte("two")))
	})
}

func TestValid(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	t.Run("accepts matching signature", func(t *testing.T) {
		t.Parallel()

		assert.True(t, Valid("key", ts, Signature("key", ts, []byte("{}")), []byte("{}"), now))
	})

	t.Run("rejects incorrect signature", func(t *testing.T) {
		t.Parallel()

		assert.False(t, Valid("key", ts, Signature("wrong", ts, []byte("{}")), []byte("{}"), now))
	})

	t.Run("rejects modified body", func(t *testing.T) {
		t.Parallel()

		assert.False(t, Valid("key", ts, Signature("key", ts, []byte("{}")), []byte("{ }"), now))
	})

	t.Run("rejects unsupported signature version", func(t *testing.T) {
		t.Parallel()

		assert.False(t, Valid("key", ts, "v2="+Signature("key", ts, []byte("{}")), []byte("{}"), now))
	})

	t.Run("rejects expired timestamp", func(t *testing.T) {
		t.Parallel()

		old := strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10)

		assert.False(t, Valid("key", old, Signature("key", old, []byte("{}")), []byte("{}"), now))
	})
}

func TestFresh(t *testing.T) {
	t.Parallel()

	now := time.Now()
	t.Run("accepts current timestamp", func(t *testing.T) {
		t.Parallel()

		assert.True(t, fresh(strconv.FormatInt(now.Unix(), 10), now))
	})

	t.Run("rejects leading zero", func(t *testing.T) {
		t.Parallel()

		assert.False(t, fresh("0"+strconv.FormatInt(now.Unix(), 10), now))
	})

	t.Run("rejects invalid integer", func(t *testing.T) {
		t.Parallel()

		assert.False(t, fresh("not-a-timestamp", now))
	})

	t.Run("rejects too old", func(t *testing.T) {
		t.Parallel()

		assert.False(t, fresh(strconv.FormatInt(now.Unix()-301, 10), now))
	})

	t.Run("rejects too far in future", func(t *testing.T) {
		t.Parallel()

		assert.False(t, fresh(strconv.FormatInt(now.Unix()+301, 10), now))
	})
}
