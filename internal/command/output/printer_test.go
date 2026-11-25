package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrinter(t *testing.T) {
	t.Parallel()

	t.Run("mixed batch prints only successes", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		format, quiet := "", false
		err := NewPrinter(&format, &quiet, &stdout)(Batch{
			Operation: OperationBan,
			Results:   []Item{{IPAddress: "203.0.113.1", Success: true}, {IPAddress: "203.0.113.2", Error: "failed"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "Banned 203.0.113.1\n", stdout.String())
	})

	t.Run("confirmation write failure is returned", func(t *testing.T) {
		t.Parallel()
		format, quiet := "", false
		err := NewPrinter(&format, &quiet, failingWriter{})(Batch{
			Operation: OperationBan,
			Results:   []Item{{IPAddress: "203.0.113.1", Success: true}},
		})
		require.ErrorContains(t, err, "write failed")
	})

	t.Run("query defaults to yaml", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		format, quiet := "", false
		require.NoError(t, NewPrinter(&format, &quiet, &stdout)(sampleResult{IP: "203.0.113.1"}))
		assert.Equal(t, "ipAddress: 203.0.113.1\n", stdout.String())
	})
}
