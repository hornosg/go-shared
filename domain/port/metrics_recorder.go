package port

// MetricKind identifies the Prometheus instrument type for a metric event.
type MetricKind string

const (
	MetricKindCounter   MetricKind = "counter"
	MetricKindGauge     MetricKind = "gauge"
	MetricKindHistogram MetricKind = "histogram"
)

// MetricUnit describes the unit of MetricEvent.Value, used to build the Prometheus metric name suffix.
type MetricUnit string

const (
	MetricUnitNone         MetricUnit = ""
	MetricUnitMilliseconds MetricUnit = "ms"
	MetricUnitSeconds      MetricUnit = "s"
	MetricUnitBytes        MetricUnit = "bytes"
	MetricUnitRequests     MetricUnit = "requests"
	MetricUnitItems        MetricUnit = "items"
)

// MetricEvent is the canonical payload for all metric observations.
// Name follows the same <domain>.<action>_<result> convention as canonical log events (ADR-002).
type MetricEvent struct {
	Name   string            // e.g., "tenant.created", "auth.login_failed"
	Kind   MetricKind        // counter / gauge / histogram
	Unit   MetricUnit        // unit of Value; used to build the Prometheus metric name suffix
	Labels map[string]string // e.g., {"plan_id": "free", "status": "active"}
	Value  float64           // 1.0 for counters; observed value for histograms and gauges
}

// MetricsRecorder is the port for emitting metric observations.
// Application-layer use cases depend on this interface; adapters (Prometheus, noop, etc.) implement it.
type MetricsRecorder interface {
	Record(event MetricEvent)
}
