// Package domain contains the portable event model of the platform EventBus.
// The Event type is deliberately simple and backward-compatible with the
// v0.1.0 eventbus used by mercadocercano/eventbus.
package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// DomainEvent is the canonical event envelope for the platform EventBus v0.2.0.
// It is backward-compatible with mercadocercano/eventbus v0.1.0 fields:
//   - ID
//   - EventType (was EventType in v0.1.0, here renamed for clarity but JSON-mapped as event_type)
//   - Payload
//   - Namespace / TenantID / UserID
//   - OccurredAt (was CreatedAt in some v0.1.0 consumers)
//   - Version
//
// New v0.2.0 fields:
//   - CorrelationID, Traceparent
//   - Channel (used when the event is also a job queue entry)
//   - Priority, DelayedUntil
//   - Attempt / MaxAttempts / DLQ metadata
type DomainEvent struct {
	ID            string          `json:"id"`
	EventType     string          `json:"event_type"`
	Version       string          `json:"version,omitempty"`
	Namespace     string          `json:"namespace,omitempty"`
	TenantID      string          `json:"tenant_id,omitempty"`
	UserID        string          `json:"user_id,omitempty"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	Traceparent   string          `json:"traceparent,omitempty"`
	Channel       string          `json:"channel,omitempty"`
	Priority      int             `json:"priority,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	OccurredAt    time.Time       `json:"occurred_at"`
	DelayedUntil  *time.Time      `json:"delayed_until,omitempty"`

	// Delivery metadata set by adapters / worker.
	Attempt     int        `json:"attempt,omitempty"`
	MaxAttempts int        `json:"max_attempts,omitempty"`
	DLQAt       *time.Time `json:"dlq_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// NewEvent builds a DomainEvent with sensible defaults.
func NewEvent(eventType, namespace, tenantID, userID string, payload any) (*DomainEvent, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &DomainEvent{
		ID:         uuid.New().String(),
		EventType:  eventType,
		Version:    "1",
		Namespace:  namespace,
		TenantID:   tenantID,
		UserID:     userID,
		Payload:    raw,
		OccurredAt: now,
		Attempt:    0,
	}, nil
}

// RawPayload returns the JSON payload as bytes.
func (e *DomainEvent) RawPayload() []byte {
	return []byte(e.Payload)
}

// UnmarshalPayload decodes the payload into v.
func (e *DomainEvent) UnmarshalPayload(v any) error {
	return json.Unmarshal(e.Payload, v)
}

// Clone returns a shallow copy suitable for mutating delivery metadata.
func (e *DomainEvent) Clone() *DomainEvent {
	if e == nil {
		return nil
	}
	cp := *e
	if e.DelayedUntil != nil {
		t := *e.DelayedUntil
		cp.DelayedUntil = &t
	}
	if e.DLQAt != nil {
		t := *e.DLQAt
		cp.DLQAt = &t
	}
	return &cp
}

// Key returns a routing key useful for queues/topics.
// Format: <namespace>.<tenant|_>.<event_type>.<version>
func (e *DomainEvent) Key() string {
	if e.Namespace == "" {
		return e.EventType
	}
	tenant := e.TenantID
	if tenant == "" {
		tenant = "_"
	}
	if e.Version == "" {
		return e.Namespace + "." + tenant + "." + e.EventType
	}
	return e.Namespace + "." + tenant + "." + e.EventType + "." + e.Version
}
