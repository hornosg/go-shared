package metrics

import (
	"testing"

	sharedport "github.com/hornosg/go-shared/domain/port"
	"github.com/stretchr/testify/assert"
)

type fakeRecorder struct {
	events []sharedport.MetricEvent
}

func (f *fakeRecorder) Record(e sharedport.MetricEvent) {
	f.events = append(f.events, e)
}

func TestEventBusRecorderPublished(t *testing.T) {
	fake := &fakeRecorder{}
	r := NewEventBusRecorder(fake)
	r.Published("email", "notification.send")

	assert.Len(t, fake.events, 1)
	assert.Equal(t, MetricPublished, fake.events[0].Name)
	assert.Equal(t, sharedport.MetricKindCounter, fake.events[0].Kind)
	assert.Equal(t, 1.0, fake.events[0].Value)
	assert.Equal(t, "email", fake.events[0].Labels["channel"])
	assert.Equal(t, "notification.send", fake.events[0].Labels["event_type"])
}

func TestEventBusRecorderDLQSize(t *testing.T) {
	fake := &fakeRecorder{}
	r := NewEventBusRecorder(fake)
	r.DLQSize("push", "notification.send", 7)

	assert.Equal(t, MetricDLQSize, fake.events[0].Name)
	assert.Equal(t, sharedport.MetricKindGauge, fake.events[0].Kind)
	assert.Equal(t, 7.0, fake.events[0].Value)
}

func TestStrconvItoa(t *testing.T) {
	assert.Equal(t, "0", strconvItoa(0))
	assert.Equal(t, "42", strconvItoa(42))
	assert.Equal(t, "-3", strconvItoa(-3))
}

func TestEventBusRecorderNilSafe(t *testing.T) {
	r := NewEventBusRecorder(nil)
	assert.NotNil(t, r)
	r.Failed("sms", "notification.send", "timeout")
}
