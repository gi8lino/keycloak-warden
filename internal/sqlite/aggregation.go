package sqlite

import (
	"context"
	"strings"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

// CountMatches counts observations with the same selectors and aggregation key.
func (t *transaction) CountMatches(ctx context.Context, criteria detection.MatchQuery) (count int, err error) {
	query, args := matchQuery(criteria)
	err = t.tx.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// matchQuery builds a parameterized count for a validated rule and matching event.
func matchQuery(criteria detection.MatchQuery) (string, []any) {
	where := []string{"received > ?", "received <= ?", "source = ?", "event_kind = ?"}
	args := []any{criteria.Since.UnixMilli(), criteria.Through.UnixMilli(), criteria.Source, criteria.Kind}
	appendSelector := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		where = append(where, column+" IN ("+strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")+")")
		for _, value := range values {
			args = append(args, value)
		}
	}
	appendSelector("event_type", criteria.Events)
	appendSelector("operation_type", criteria.Operations)
	appendSelector("resource_type", criteria.Resources)
	if criteria.SuccessOnly {
		where = append(where, "event_error = ''")
	}
	key, realm := criteria.Key, criteria.IdentityRealm
	switch criteria.GroupBy {
	case detection.GroupUser:
		where = append(where, "user_id = ?", "identity_realm = ?")
		args = append(args, key, realm)
	case detection.GroupRealm:
		where = append(where, "realm_id = ?")
		args = append(args, key)
	default:
		where = append(where, "ip = ?")
		args = append(args, key)
	}
	if criteria.EligibleOnly {
		where = append(where, "ban_eligible = 1")
	}
	if criteria.CurrentGeneration {
		where = append(where, `generation = COALESCE((
            SELECT failure_generation
            FROM decisions
            WHERE ip = ?
        ), 0)`)
		args = append(args, criteria.Key)
	}
	if criteria.ExcludeEventID != "" {
		where = append(where, "event_id <> ?")
		args = append(args, criteria.ExcludeEventID)
	}
	projection := "1"
	switch criteria.Distinct {
	case detection.GroupIP:
		projection = "DISTINCT ip"
		where = append(where, "ip <> ''")
	case detection.GroupUser:
		projection = "DISTINCT identity_realm, user_id"
		where = append(where, "identity_realm <> ''", "user_id <> ''")
	}
	query := `
SELECT COUNT(*)
FROM (
    SELECT ` + projection + `
    FROM event_observations
    WHERE ` + strings.Join(where, "\n        AND ") + `
)
`
	return query, args
}
