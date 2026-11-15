package bans

import (
	"fmt"
	"math"
)

// HistoryPageSize limits destination/revision groups returned by an inspection.
const HistoryPageSize = 16

// HistoryOffset validates a one-based history page and computes its SQLite offset.
// It rejects zero, negative, and overflowing page numbers before persistence.
func HistoryOffset(page int) (int64, error) {
	if page < 1 || int64(page-1) > math.MaxInt64/HistoryPageSize {
		return 0, fmt.Errorf("%w: history page must be a positive number within range", ErrInvalid)
	}
	return int64(page-1) * HistoryPageSize, nil
}
