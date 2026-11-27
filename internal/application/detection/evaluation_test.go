package detection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countFunc func(context.Context, MatchQuery) (int, error)

func (f countFunc) CountMatches(ctx context.Context, query MatchQuery) (int, error) {
	return f(ctx, query)
}

func TestCrossed(t *testing.T) {
	t.Parallel()

	t.Run("records each threshold one event", func(t *testing.T) {
		t.Parallel()

		rule := Rule{Aggregation: Aggregation{Threshold: 1}}
		crossed, err := Crossed(t.Context(), nil, rule, MatchQuery{}, "event")
		require.NoError(t, err)
		assert.True(t, crossed)
	})

	t.Run("excludes triggering event from previous count", func(t *testing.T) {
		t.Parallel()

		rule := Rule{Aggregation: Aggregation{Threshold: 5}}
		counter := countFunc(func(_ context.Context, query MatchQuery) (int, error) {
			assert.Equal(t, "event", query.ExcludeEventID)
			return 4, nil
		})
		crossed, err := Crossed(t.Context(), counter, rule, MatchQuery{}, "event")
		require.NoError(t, err)
		assert.True(t, crossed)
	})

	t.Run("does not repeat a threshold occurrence", func(t *testing.T) {
		t.Parallel()

		rule := Rule{Aggregation: Aggregation{Threshold: 5}}
		counter := countFunc(func(context.Context, MatchQuery) (int, error) {
			return 5, nil
		})
		crossed, err := Crossed(t.Context(), counter, rule, MatchQuery{}, "event")
		require.NoError(t, err)
		assert.False(t, crossed)
	})
}
