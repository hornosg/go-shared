package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent(t *testing.T) {
	e, err := NewEvent("notification.send", "mc", "tenant-1", "user-1", map[string]string{"foo": "bar"})
	require.NoError(t, err)

	assert.NotEmpty(t, e.ID)
	assert.Equal(t, "notification.send", e.EventType)
	assert.Equal(t, "mc", e.Namespace)
	assert.Equal(t, "tenant-1", e.TenantID)
	assert.Equal(t, "user-1", e.UserID)
	assert.Equal(t, "1", e.Version)
	assert.NotZero(t, e.OccurredAt)

	var payload map[string]string
	require.NoError(t, e.UnmarshalPayload(&payload))
	assert.Equal(t, "bar", payload["foo"])
}

func TestDomainEventKey(t *testing.T) {
	e := &DomainEvent{Namespace: "mc", TenantID: "t1", EventType: "notification.send", Version: "1"}
	assert.Equal(t, "mc.t1.notification.send.1", e.Key())

	e2 := &DomainEvent{Namespace: "", EventType: "ping"}
	assert.Equal(t, "ping", e2.Key())

	e3 := &DomainEvent{Namespace: "mc", EventType: "ping"}
	assert.Equal(t, "mc._.ping", e3.Key())
}

func TestDomainEventClone(t *testing.T) {
	now := time.Now()
	e := &DomainEvent{ID: "1", DelayedUntil: &now, DLQAt: &now}
	cp := e.Clone()
	assert.Equal(t, e.ID, cp.ID)
	assert.NotSame(t, e.DelayedUntil, cp.DelayedUntil)
	assert.NotSame(t, e.DLQAt, cp.DLQAt)
	assert.Equal(t, *e.DelayedUntil, *cp.DelayedUntil)
}

func TestDomainEventMarshalBackwardCompat(t *testing.T) {
	now := time.Now()
	e := &DomainEvent{
		ID:         "evt-123",
		EventType:  "onboarding.tenant.registered",
		Version:    "1",
		Namespace:  "mc",
		TenantID:   "tenant-123",
		UserID:     "user-123",
		Payload:    json.RawMessage(`{"x":1}`),
		OccurredAt: now,
	}
	data, err := json.Marshal(e)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"event_type":"onboarding.tenant.registered"`)
	assert.Contains(t, string(data), `"id":"evt-123"`)
}
