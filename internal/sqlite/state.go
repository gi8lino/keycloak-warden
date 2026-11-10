package sqlite

import "github.com/gi8lino/keycloak-warden/internal/application/decisions"

// stateFromActive maps the persisted SQLite boolean to the domain state.
func stateFromActive(active bool) decisions.State {
	if active {
		return decisions.StateBanned
	}
	return decisions.StateUnbanned
}
