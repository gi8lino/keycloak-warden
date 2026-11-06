package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchWriteText(t *testing.T) {
	t.Parallel()

	t.Run("summarizes a mixed ban batch without writing failures as successes", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer
		batch := Batch{Operation: "ban", Results: []Item{
			{IPAddress: "203.0.113.10", Success: true},
			{IPAddress: "203.0.113.20", Error: "rejected"},
		}, Succeeded: 1, Failed: 1}

		require.NoError(t, batch.WriteText(&out))
		assert.Equal(t, "Banned 203.0.113.10\n1 succeeded, 1 failed\n", out.String())
	})

	t.Run("describes unbanned addresses", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer
		batch := Batch{Operation: "unban", Results: []Item{{IPAddress: "203.0.113.10", Success: true}}, Succeeded: 1}

		require.NoError(t, batch.WriteText(&out))
		assert.Equal(t, "Unbanned 203.0.113.10\n1 succeeded, 0 failed\n", out.String())
	})
}
