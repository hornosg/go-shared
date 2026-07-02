package metrics

import (
	sharedport "github.com/hornosg/go-shared/domain/port"
)

// EventBus metric event names. Adapters can use either these helpers or the
// shared MetricsRecorder port; this package centralizes the naming convention.
const (
	MetricPublished   = "eventbus.published"
	MetricConsumed    = "eventbus.consumed"
	MetricFailed      = "eventbus.failed"
	MetricRetried     = "eventbus.retried"
	MetricDLQ         = "eventbus.dlq"
	MetricDLQSize     = "eventbus.dlq_size"
	MetricPublishTime = "eventbus.publish_time"
	MetricConsumeTime = "eventbus.consume_time"
)

// EventBusRecorder is a thin wrapper around the generic MetricsRecorder port.
// It is not a hard dependency on Prometheus so the eventbus stays testable.
type EventBusRecorder struct {
	recorder sharedport.MetricsRecorder
}

// NewEventBusRecorder builds a recorder backed by the provided MetricsRecorder.
// A nil recorder is safe: it falls back to a no-op implementation.
func NewEventBusRecorder(recorder sharedport.MetricsRecorder) *EventBusRecorder {
	if recorder == nil {
		recorder = noopRecorder{}
	}
	return &EventBusRecorder{recorder: recorder}
}

// Published increments the published counter for a channel / event type.
func (r *EventBusRecorder) Published(channel, eventType string) {
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricPublished,
		Kind:   sharedport.MetricKindCounter,
		Value:  1,
		Labels: labels(channel, eventType),
	})
}

// Consumed increments the consumed counter.
func (r *EventBusRecorder) Consumed(channel, eventType string) {
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricConsumed,
		Kind:   sharedport.MetricKindCounter,
		Value:  1,
		Labels: labels(channel, eventType),
	})
}

// Failed increments the failed counter with a reason label.
func (r *EventBusRecorder) Failed(channel, eventType, reason string) {
	l := labels(channel, eventType)
	l["reason"] = reason
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricFailed,
		Kind:   sharedport.MetricKindCounter,
		Value:  1,
		Labels: l,
	})
}

// Retried increments the retried counter.
func (r *EventBusRecorder) Retried(channel, eventType string, attempt int) {
	l := labels(channel, eventType)
	l["attempt"] = strconvItoa(attempt)
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricRetried,
		Kind:   sharedport.MetricKindCounter,
		Value:  1,
		Labels: l,
	})
}

// DLQ increments the DLQ counter.
func (r *EventBusRecorder) DLQ(channel, eventType string) {
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricDLQ,
		Kind:   sharedport.MetricKindCounter,
		Value:  1,
		Labels: labels(channel, eventType),
	})
}

// DLQSize sets the current dead-letter queue size gauge.
func (r *EventBusRecorder) DLQSize(channel, eventType string, size float64) {
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricDLQSize,
		Kind:   sharedport.MetricKindGauge,
		Value:  size,
		Labels: labels(channel, eventType),
	})
}

// PublishTime records the publish latency histogram in milliseconds.
func (r *EventBusRecorder) PublishTime(channel, eventType string, ms float64) {
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricPublishTime,
		Kind:   sharedport.MetricKindHistogram,
		Unit:   sharedport.MetricUnitMilliseconds,
		Value:  ms,
		Labels: labels(channel, eventType),
	})
}

// ConsumeTime records the handler latency histogram in milliseconds.
func (r *EventBusRecorder) ConsumeTime(channel, eventType string, ms float64) {
	r.recorder.Record(sharedport.MetricEvent{
		Name:   MetricConsumeTime,
		Kind:   sharedport.MetricKindHistogram,
		Unit:   sharedport.MetricUnitMilliseconds,
		Value:  ms,
		Labels: labels(channel, eventType),
	})
}

func labels(channel, eventType string) map[string]string {
	l := map[string]string{
		"channel":    channel,
		"event_type": eventType,
	}
	return l
}

// strconvItoa is a tiny helper to avoid importing strconv in this package.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

type noopRecorder struct{}

func (noopRecorder) Record(_ sharedport.MetricEvent) {}
