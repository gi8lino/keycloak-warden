package output

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/bans"
	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

func TestRecordsWriteText(t *testing.T) {
	t.Parallel()
	deadline := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

	t.Run("includes decision sources and delivery acknowledgements", func(t *testing.T) {
		t.Parallel()
		records := Records{{
			Decision: decisions.Decision{ID: "one", IP: "203.0.113.10", State: decisions.StateBanned, Revision: 4, ExpiresAt: deadline},
			Sources: []bans.Source{
				{Kind: bans.SourceAutomatic, ExpiresAt: deadline},
				{Kind: bans.SourceManual, ExpiresAt: deadline, Reason: "Incident"},
			},
			Deliveries: []decisions.Acknowledgement{{Destination: "webhook.receiver", Revision: 4}},
		}}
		var out bytes.Buffer
		require.NoError(t, records.WriteText(&out))
		assert.Contains(t, out.String(), "ID: one\n")
		assert.Contains(t, out.String(), "IP: 203.0.113.10")
		assert.Contains(t, out.String(), "State: banned")
		assert.Contains(t, out.String(), "Sources:\n  automatic:")
		assert.Contains(t, out.String(), "manual:")
		assert.Contains(t, out.String(), "Incident")
		assert.Contains(t, out.String(), "webhook.receiver: revision 4")
		assert.NotContains(t, out.String(), "Failures")
	})

	t.Run("shows no sources for released historical decision", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		require.NoError(t, (Records{{Decision: decisions.Decision{ID: "released", State: decisions.StateUnbanned}}}).WriteText(&out))
		assert.Contains(t, out.String(), "Sources: none")
		assert.Contains(t, out.String(), "Deliveries: none")
	})

	t.Run("separates multiple records", func(t *testing.T) {
		t.Parallel()
		records := Records{
			{Decision: decisions.Decision{ID: "one"}},
			{Decision: decisions.Decision{ID: "two"}},
		}
		var out bytes.Buffer
		require.NoError(t, records.WriteText(&out))
		assert.Contains(t, out.String(), "Deliveries: none\n\nID: two\n")
	})

	t.Run("explains an empty active list", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		require.NoError(t, Records{}.WriteText(&out))
		assert.Equal(t, "No active bans\n", out.String())
	})

	t.Run("propagates write errors", func(t *testing.T) {
		t.Parallel()
		require.Error(t, (Records{{Decision: decisions.Decision{ID: "one"}}}).WriteText(failingWriter{}))
	})
}
