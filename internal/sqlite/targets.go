package sqlite

import "context"

// ManagedTargets returns destinations that still own a banned decision or an
// unacknowledged revision. It reports persisted facts without choosing a policy.
func (s *Store) ManagedTargets(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT q.destination
FROM deliveries AS q
JOIN decisions AS d USING (ip)
WHERE d.state = 'banned' OR q.acknowledged < d.revision
ORDER BY q.destination
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
