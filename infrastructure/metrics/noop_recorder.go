package metrics

import sharedport "github.com/hornosg/go-shared/domain/port"

// NoopRecorder discards all metric events. Use in unit tests.
type NoopRecorder struct{}

func (NoopRecorder) Record(_ sharedport.MetricEvent) {}
