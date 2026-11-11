package output

import "github.com/gi8lino/keycloak-warden/internal/application/bans"

// Records is a collection of decisions with active sources and delivery acknowledgements.
type Records []bans.Record
