package sqlite

import (
	"github.com/gi8lino/keycloak-warden/pkg/decisionstate"
)

// stateFromActive maps the persisted SQLite boolean to the domain state.
func stateFromActive(active bool) decisionstate.State {
	if active {
		return decisionstate.StateBanned
	}
	return decisionstate.StateUnbanned
}
