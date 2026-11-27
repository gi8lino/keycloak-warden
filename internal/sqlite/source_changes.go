package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

const sourceChangesLimit = 50

// readSourceChanges retrieves bounded, newest-first source mutations for an inspected decision.
func readSourceChanges(ctx context.Context, tx *sql.Tx, ip string) ([]model.SourceChange, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, kind, action, expires, reason, changed_at
FROM source_changes
WHERE ip = ?
ORDER BY id DESC
LIMIT ?
`, ip, sourceChangesLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	changes := []model.SourceChange{}
	for rows.Next() {
		var entry model.SourceChange
		var expires, changedAt int64
		if err := rows.Scan(&entry.ID, &entry.Kind, &entry.Action, &expires, &entry.Reason, &changedAt); err != nil {
			return nil, err
		}
		entry.ExpiresAt = time.UnixMilli(expires).UTC()
		entry.ChangedAt = time.UnixMilli(changedAt).UTC()
		changes = append(changes, entry)
	}
	return changes, rows.Err()
}
