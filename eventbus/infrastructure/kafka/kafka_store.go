// Package kafka contains the Kafka adapter stub for the platform EventBus.
package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/ports"
)

// Config holds Kafka-specific connection parameters.
type Config struct {
	Brokers []string
	Topic   string
	GroupID string
}

// Store implements ports.Store on top of Kafka.
// The actual client is stored as interface{} to keep the go-shared dependency tree small.
type Store struct {
	config Config
	client any
}

// NewStore creates a store backed by Kafka.
func NewStore(config Config, client any) *Store {
	return &Store{config: config, client: client}
}

func (s *Store) Save(ctx context.Context, event *domain.DomainEvent) error {
	if s.client == nil {
		return errors.New("kafka: client not configured")
	}
	if event == nil || event.EventType == "" {
		return errors.New("kafka: event type is required")
	}
	_ = ctx
	return fmt.Errorf("kafka: Save not implemented in v0.2.0 stub")
}

func (s *Store) SaveBatch(ctx context.Context, events []*domain.DomainEvent) error {
	for _, e := range events {
		if err := s.Save(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Poll(ctx context.Context, eventType string, batchSize int) ([]*domain.DomainEvent, error) {
	if s.client == nil {
		return nil, errors.New("kafka: client not configured")
	}
	_ = ctx
	_ = eventType
	_ = batchSize
	return nil, fmt.Errorf("kafka: Poll not implemented in v0.2.0 stub")
}

func (s *Store) MarkProcessed(ctx context.Context, eventID string) error {
	if s.client == nil {
		return errors.New("kafka: client not configured")
	}
	_ = ctx
	_ = eventID
	return fmt.Errorf("kafka: MarkProcessed not implemented in v0.2.0 stub")
}

func (s *Store) MarkFailed(ctx context.Context, eventID string, attempt int, err error, maxAttempts int) error {
	if s.client == nil {
		return errors.New("kafka: client not configured")
	}
	_ = ctx
	_ = eventID
	_ = attempt
	_ = err
	_ = maxAttempts
	return fmt.Errorf("kafka: MarkFailed not implemented in v0.2.0 stub")
}

func (s *Store) MoveToDLQ(ctx context.Context, event *domain.DomainEvent, reason string) error {
	if s.client == nil {
		return errors.New("kafka: client not configured")
	}
	_ = ctx
	_ = event
	_ = reason
	return fmt.Errorf("kafka: MoveToDLQ not implemented in v0.2.0 stub")
}

func (s *Store) ListDLQ(ctx context.Context, eventType string, limit int) ([]*domain.DomainEvent, error) {
	if s.client == nil {
		return nil, errors.New("kafka: client not configured")
	}
	_ = ctx
	_ = eventType
	_ = limit
	return nil, fmt.Errorf("kafka: ListDLQ not implemented in v0.2.0 stub")
}

func (s *Store) Close() error {
	return nil
}

// encode serializes a DomainEvent for Kafka.
func encode(event *domain.DomainEvent) ([]byte, error) {
	return json.Marshal(map[string]any{
		"id":         event.ID,
		"event_type": event.EventType,
		"payload":    string(event.Payload),
		"metadata": map[string]string{
			"channel":     event.Channel,
			"namespace":   event.Namespace,
			"tenant_id":   event.TenantID,
			"version":     event.Version,
			"occurred_at": event.OccurredAt.Format(time.RFC3339Nano),
		},
	})
}

var _ ports.Store = (*Store)(nil)
