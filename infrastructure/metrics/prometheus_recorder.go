package metrics

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	sharedport "github.com/hornosg/go-shared/domain/port"
)

// PrometheusRecorder implements MetricsRecorder by routing MetricEvents to Prometheus instruments.
// Instruments are lazily registered on first use; the metric name is derived from the event name
// following Prometheus naming conventions (dots → underscores, unit/kind suffix appended).
//
// Name derivation examples:
//
//	"tenant.created"   + counter              → tenant_created_total
//	"http.request"     + histogram + ms       → http_request_ms
//	"cache.size"       + gauge    + bytes     → cache_size_bytes
type PrometheusRecorder struct {
	mu         sync.Mutex
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec
}

func NewPrometheusRecorder() *PrometheusRecorder {
	return &PrometheusRecorder{
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
	}
}

func (r *PrometheusRecorder) Record(event sharedport.MetricEvent) {
	labelNames := labelKeys(event.Labels)
	labelValues := labelVals(event.Labels, labelNames)
	base := prometheusName(event.Name)

	switch event.Kind {
	case sharedport.MetricKindCounter:
		r.counter(base, labelNames).WithLabelValues(labelValues...).Add(event.Value)
	case sharedport.MetricKindGauge:
		name := base
		if event.Unit != sharedport.MetricUnitNone {
			name += "_" + string(event.Unit)
		}
		r.gauge(name, labelNames).WithLabelValues(labelValues...).Set(event.Value)
	case sharedport.MetricKindHistogram:
		name := base
		if event.Unit != sharedport.MetricUnitNone {
			name += "_" + string(event.Unit)
		}
		r.histogram(name, labelNames).WithLabelValues(labelValues...).Observe(event.Value)
	}
}

func (r *PrometheusRecorder) counter(name string, labelNames []string) *prometheus.CounterVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name + "_total"}, labelNames)
	if err := prometheus.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			c = are.ExistingCollector.(*prometheus.CounterVec)
		}
	}
	r.counters[name] = c
	return c
}

func (r *PrometheusRecorder) gauge(name string, labelNames []string) *prometheus.GaugeVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name}, labelNames)
	if err := prometheus.Register(g); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			g = are.ExistingCollector.(*prometheus.GaugeVec)
		}
	}
	r.gauges[name] = g
	return g
}

func (r *PrometheusRecorder) histogram(name string, labelNames []string) *prometheus.HistogramVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Buckets: prometheus.DefBuckets}, labelNames)
	if err := prometheus.Register(h); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			h = are.ExistingCollector.(*prometheus.HistogramVec)
		}
	}
	r.histograms[name] = h
	return h
}

// prometheusName converts "tenant.created" → "tenant_created".
func prometheusName(eventName string) string {
	return strings.ReplaceAll(eventName, ".", "_")
}

func labelKeys(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	return keys
}

func labelVals(labels map[string]string, keys []string) []string {
	vals := make([]string, len(keys))
	for i, k := range keys {
		vals[i] = labels[k]
	}
	return vals
}
