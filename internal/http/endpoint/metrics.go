package endpoint

import "net/http"

// EventMetrics records successfully processed Snitch events and automatic decisions.
type EventMetrics interface {
	// RecordProcessedEvent attributes an event and optional ban decision to its source realm.
	RecordProcessedEvent(realmID, eventKind, eventType string, automaticBan bool)
	// RecordIncident counts a committed rule threshold hit.
	RecordIncident(rule string)
}

// Metrics supplies Prometheus exposition, event counts, and HTTP request instrumentation.
type Metrics interface {
	EventMetrics
	// Metrics returns the Prometheus exposition handler.
	Metrics() http.Handler
	// InstrumentHTTP wraps the completed HTTP application with request instrumentation.
	InstrumentHTTP(http.Handler) http.Handler
}
