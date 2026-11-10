// Package metrics provides optional Prometheus instrumentation for Warden.
package metrics

import (
	"cmp"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry owns Warden's private metrics registry and collectors.
// No collectors are allocated when collection is disabled.
type Registry struct {
	// enabled avoids metrics allocation and instrumentation when disabled.
	enabled bool
	// registry owns only explicitly registered Warden collectors.
	registry *prometheus.Registry
	// httpRequests counts application responses by stable route and code.
	httpRequests *prometheus.CounterVec
	// httpDuration measures application request latency.
	httpDuration *prometheus.HistogramVec
	// snitchEvents counts authenticated events processed by source realm and native type.
	snitchEvents *prometheus.CounterVec
	// automaticBanDecisions counts decisions by the realm of the triggering event.
	automaticBanDecisions *prometheus.CounterVec
	// deliveryAttempts counts outbound delivery attempts by destination and outcome.
	deliveryAttempts *prometheus.CounterVec
	// deliveryDuration measures outbound provider request latency.
	deliveryDuration *prometheus.HistogramVec
}

// NewRegistry constructs the private Prometheus registry when enabled.
func NewRegistry(enabled bool, version string) *Registry {
	if !enabled {
		return &Registry{}
	}

	registry := prometheus.NewRegistry()

	httpRequests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_http_requests_total",
		Help: "Completed HTTP requests by method, matched route, and response code.",
	}, []string{"method", "route", "code"})
	httpDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "warden_http_request_duration_seconds",
		Help:    "HTTP request duration by method and matched route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})
	snitchEvents := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_snitch_events_total",
		Help: "Authenticated Snitch HTTP events successfully processed (including duplicate event IDs), by realm and event type.",
	}, []string{"realm", "event_type"})
	automaticBanDecisions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_automatic_ban_decisions_total",
		Help: "Automatic ban decisions by triggering event realm; the detection threshold remains global by IP.",
	}, []string{"trigger_realm"})
	deliveryAttempts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_delivery_attempts_total",
		Help: "Outbound destination delivery attempts by destination and outcome.",
	}, []string{"destination", "outcome"})
	deliveryDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "warden_delivery_duration_seconds",
		Help:    "Outbound destination delivery duration by destination.",
		Buckets: prometheus.DefBuckets,
	}, []string{"destination"})
	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "warden_build_info",
		Help:        "Warden build metadata.",
		ConstLabels: prometheus.Labels{"version": version},
	})
	buildInfo.Set(1)

	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		httpRequests,
		httpDuration,
		snitchEvents,
		automaticBanDecisions,
		deliveryAttempts,
		deliveryDuration,
		buildInfo,
	)

	return &Registry{
		enabled:               true,
		registry:              registry,
		httpRequests:          httpRequests,
		httpDuration:          httpDuration,
		snitchEvents:          snitchEvents,
		automaticBanDecisions: automaticBanDecisions,
		deliveryAttempts:      deliveryAttempts,
		deliveryDuration:      deliveryDuration,
	}
}

// RecordProcessedEvent counts accepted Snitch requests by realm, including duplicate event IDs.
// A ban decision is attributed to the realm that sent the triggering event, not
// necessarily every realm whose failures contributed to the global IP threshold.
func (r *Registry) RecordProcessedEvent(realmID, eventType string, automaticBan bool) {
	if r == nil || !r.enabled {
		return
	}

	realm := cmp.Or(strings.TrimSpace(realmID), "unknown")
	r.snitchEvents.WithLabelValues(realm, eventType).Inc()

	if automaticBan {
		r.automaticBanDecisions.WithLabelValues(realm).Inc()
	}
}

// Metrics returns the exposition handler, or a 404 handler when disabled.
func (r *Registry) Metrics() http.Handler {
	if r == nil || !r.enabled {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// InstrumentHTTP records request counts and latency using bounded route labels.
func (r *Registry) InstrumentHTTP(next http.Handler) http.Handler {
	if r == nil || !r.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		response := &statusWriter{ResponseWriter: w}

		next.ServeHTTP(response, request)

		status := response.status
		if status == 0 {
			status = http.StatusOK
		}
		method, route := requestLabels(request)
		r.httpRequests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
		r.httpDuration.WithLabelValues(method, route).Observe(time.Since(started).Seconds())
	})
}

// statusWriter captures the response code and preserves ResponseController support.
type statusWriter struct {
	// ResponseWriter forwards response operations to the underlying transport.
	http.ResponseWriter
	// status records the first final HTTP status code.
	status int
}

// Unwrap returns the underlying writer to http.ResponseController.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader records the first non-informational response status.
func (w *statusWriter) WriteHeader(status int) {
	if status >= http.StatusOK && w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write records the implicit HTTP 200 status when writing the body.
func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// requestLabels returns bounded labels and never uses a raw request path.
func requestLabels(request *http.Request) (method, route string) {
	method = metricMethod(request.Method)
	route = strings.TrimSpace(request.Pattern)
	if _, path, ok := strings.Cut(route, " "); ok {
		route = strings.TrimSpace(path)
	}

	return method, cmp.Or(route, "unmatched")
}

// metricMethod limits caller-controlled HTTP methods to a fixed label vocabulary.
func metricMethod(method string) string {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
		http.MethodPatch:
		return method
	default:
		return "OTHER"
	}
}
