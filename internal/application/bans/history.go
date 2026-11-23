package bans

import (
	"fmt"
	"math"
)

const (
	// HistoryPageSize limits destination/revision groups returned by an inspection.
	HistoryPageSize = 16
	// HistoryAttemptLimit bounds completed attempts returned per destination/revision group.
	HistoryAttemptLimit = 16
	// HistoryErrorCharLimit bounds the error excerpt returned per completed attempt.
	HistoryErrorCharLimit = 512
)

// HistoryPage contains validated read bounds for one decision history request.
type HistoryPage struct {
	// Number is the one-based page used in response metadata.
	Number int
	// Offset skips the groups belonging to earlier pages.
	Offset int64
	// Groups limits the number of destination/revision groups.
	Groups int
	// Attempts limits the most recent completed attempts returned per group.
	Attempts int
	// ErrorCharacters bounds the provider error excerpt on each attempt.
	ErrorCharacters int
	// ThroughRevision excludes newer revisions; zero selects the latest revision.
	ThroughRevision int64
}

// NewHistoryPage validates the requested range and supplies the inspection read policy.
func NewHistoryPage(page int, throughRevision int64) (HistoryPage, error) {
	if page < 1 || int64(page-1) > math.MaxInt64/HistoryPageSize {
		return HistoryPage{}, fmt.Errorf("%w: history page must be a positive number within range", ErrInvalid)
	}
	if throughRevision < 0 {
		return HistoryPage{}, fmt.Errorf("%w: history revision must be nonnegative", ErrInvalid)
	}
	return HistoryPage{
		Number:          page,
		Offset:          int64(page-1) * HistoryPageSize,
		Groups:          HistoryPageSize,
		Attempts:        HistoryAttemptLimit,
		ErrorCharacters: HistoryErrorCharLimit,
		ThroughRevision: throughRevision,
	}, nil
}
