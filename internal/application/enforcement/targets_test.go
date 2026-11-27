package enforcement

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedTargetReader supplies the persisted destination ownership facts.
type fixedTargetReader struct {
	// names lists destinations currently owned by the fake store.
	names []string
	// err is the simulated storage failure.
	err error
}

// ManagedTargets returns the configured ownership names and simulated lookup error.
func (f fixedTargetReader) ManagedTargets(context.Context) ([]string, error) {
	return f.names, f.err
}

func TestValidateTargets(t *testing.T) {
	t.Parallel()

	t.Run("keeps managed targets", func(t *testing.T) {
		t.Parallel()
		err := ValidateTargets(t.Context(), fixedTargetReader{names: []string{"edge"}}, []string{"edge", "other"})
		require.NoError(t, err)
	})

	t.Run("rejects abandoned managed targets", func(t *testing.T) {
		t.Parallel()
		err := ValidateTargets(t.Context(), fixedTargetReader{names: []string{"edge"}}, []string{"other"})
		require.ErrorContains(t, err, `destination "edge" has managed decisions`)
	})

	t.Run("accepts empty ownership", func(t *testing.T) {
		t.Parallel()
		err := ValidateTargets(t.Context(), fixedTargetReader{}, nil)
		require.NoError(t, err)
	})

	t.Run("returns persistence errors", func(t *testing.T) {
		t.Parallel()
		want := errors.New("database error")
		err := ValidateTargets(t.Context(), fixedTargetReader{err: want}, nil)
		assert.ErrorIs(t, err, want)
	})
}
