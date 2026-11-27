package detection

import "context"

// Evaluation describes one rule's count for the current event.
type Evaluation struct {
	// Rule identifies the evaluated policy.
	Rule string
	// Count is the matching observation count.
	Count int
	// Threshold is the configured minimum.
	Threshold int
}

// Counter counts observations using explicit selection criteria.
type Counter interface {
	CountMatches(context.Context, MatchQuery) (int, error)
}

// Crossed reports whether a qualifying event crossed the threshold. Threshold-one
// rules record each matching event, making them suitable for audit monitoring.
func Crossed(ctx context.Context, counter Counter, rule Rule, query MatchQuery, id string) (bool, error) {
	if rule.Aggregation.Threshold == 1 {
		return true, nil
	}

	query.ExcludeEventID = id
	previous, err := counter.CountMatches(ctx, query)

	return previous < rule.Aggregation.Threshold, err
}
