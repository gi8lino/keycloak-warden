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

func TestBansWriteText(t *testing.T) {
	t.Parallel()

	t.Run("shows both automatic and manual sources", func(t *testing.T) {
		t.Parallel()

		deadline := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
		list := Bans{{Decision: decisions.Decision{IP: "203.0.113.10", ExpiresAt: deadline}, Sources: []bans.Source{
			{Kind: bans.SourceAutomatic, ExpiresAt: deadline},
			{Kind: bans.SourceManual, ExpiresAt: deadline, Reason: "Incident"},
		}}}
		var output bytes.Buffer

		require.NoError(t, list.WriteText(&output))
		assert.Contains(t, output.String(), "203.0.113.10")
		assert.Contains(t, output.String(), "automatic")
		assert.Contains(t, output.String(), "manual")
		assert.Contains(t, output.String(), "Incident")
	})

	t.Run("explains an empty list", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer

		require.NoError(t, Bans{}.WriteText(&output))
		assert.Equal(t, "No active bans\n", output.String())
	})
}

func TestInspectionWriteText(t *testing.T) {
	t.Parallel()

	t.Run("prints decision and delivery status", func(t *testing.T) {
		t.Parallel()

		view := Inspection(decisions.Inspection{
			Decision:   decisions.Decision{ID: "one", IP: "203.0.113.10", Active: true, Revision: 4},
			Deliveries: []decisions.Acknowledgement{{Destination: "edge", Revision: 4}},
		})
		var output bytes.Buffer

		require.NoError(t, view.WriteText(&output))
		assert.Contains(t, output.String(), "IP: 203.0.113.10")
		assert.Contains(t, output.String(), "State: active")
		assert.Contains(t, output.String(), "edge: revision 4")
	})
}

func TestInspectionsWriteText(t *testing.T) {
	t.Parallel()

	t.Run("prints each decision with a blank separator", func(t *testing.T) {
		t.Parallel()
		views := Inspections{
			{Decision: decisions.Decision{ID: "one", IP: "203.0.113.10"}, Deliveries: []decisions.Acknowledgement{}},
			{Decision: decisions.Decision{ID: "two", IP: "203.0.113.11"}, Deliveries: []decisions.Acknowledgement{}},
		}
		var out bytes.Buffer
		require.NoError(t, views.WriteText(&out))
		assert.Contains(t, out.String(), "ID: one\n")
		assert.Contains(t, out.String(), "ID: two\n")
		assert.Contains(t, out.String(), "Deliveries: none\n\nID: two\n")
	})

	t.Run("propagates write failures", func(t *testing.T) {
		t.Parallel()
		views := Inspections{{Decision: decisions.Decision{ID: "one"}}}
		require.Error(t, views.WriteText(failingWriter{}))
	})
}
