package sqlite

import (
	"context"
	"fmt"
	"slices"

	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// ValidateTargets refuses to abandon pending ownership of external bans.
// Call it at startup with the resolved destination names before workers begin.
func (s *Store) ValidateTargets(ctx context.Context, targets []string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT q.destination
FROM deliveries AS q
JOIN decisions AS d USING (ip)
WHERE d.state = ? OR q.acknowledged < d.revision
`, decisionstate.StateBanned)
	if err != nil {
		return err
	}
	defer rows.Close() // nolint:errcheck

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if !slices.Contains(targets, name) {
			return fmt.Errorf("destination %q has managed decisions; keep it configured until release", name)
		}
	}
	return rows.Err()
}
