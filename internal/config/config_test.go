package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	t.Run("accepts a valid detection rule", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Rule: detection.Rule{Threshold: 5, Window: time.Minute, Ban: 15 * time.Minute}}

		require.NoError(t, cfg.Validate())
	})

	t.Run("rejects a missing detection threshold", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Rule: detection.Rule{Window: time.Minute, Ban: 15 * time.Minute}}

		require.ErrorContains(t, cfg.Validate(), "threshold")
	})
}
