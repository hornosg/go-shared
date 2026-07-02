// Package rabbitmq contains the RabbitMQ adapter stub for the platform EventBus.
package rabbitmq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/ports"
)

// Config holds RabbitMQ-specific connection parameters.
type Config struct {
	URL      string
	Exchange string
	Queue    string
}

// Store implements ports.Store on top of RabbitMQ.
type Store struct {
	config Config
	client any
}

// NewStore creates a store backed by RabbitMQ.
func NewStore(config Config, client any) *Store {
	return &Store{config: config, client: client}
}

func (s *Store) Save(ctx context.Context, event *domain.DomainEvent) error {
	if s.client == nil {
		return errors.New("rabbitmq: client not configured")
	}
	if event == nil || event.EventType == "" {
		return errors.New("rabbitmq: event type is required")
	}
	_ = ctx
	return fmt.Errorf("rabbitmq: Save not implemented in v0.2.0 stub")
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
		return nil, errors.New("rabbitmq: client not configured")
	}
	_ = ctx
	_ = eventType
	_ = batchSize
	return nil, fmt.Errorf("rabbitmq: Poll not implemented in v0.2.0 stub")
}

func (s *Store) MarkProcessed(ctx context.Context, eventID string) error {
	if s.client == nil {
		return errors.New("rabbitmq: client not configured")
	}
	_ = ctx
	_ = eventID
	return fmt.Errorf("rabbitmq: MarkProcessed not implemented in v0.2.0 stub")
}

func (s *Store) MarkFailed(ctx context.Context, eventID string, attempt int, err error, maxAttempts int) error {
	if s.client == nil {
		return errors.New("rabbitmq: client not configured")
	}
	_ = ctx
	_ = eventID
	_ = attempt
	_ = err
	_ = maxAttempts
	return fmt.Errorf("rabbitmq: MarkFailed not implemented in v0.2.0 stub")
}

func (s *Store) MoveToDLQ(ctx context.Context, event *domain.DomainEvent, reason string) error {
	if s.client == nil {
		return errors.New("rabbitmq: client not configured")
	}
	_ = ctx
	_ = event
	_ = reason
	return fmt.Errorf("rabbitmq: MoveToDLQ not implemented in v0.2.0 stub")
}

func (s *Store) ListDLQ(ctx context.Context, eventType string, limit int) ([]*domain.DomainEvent, error) {
	if s.client == nil {
		return nil, errors.New("rabbitmq: client not configured")
	}
	_ = ctx
	_ = eventType
	_ = limit
	return nil, fmt.Errorf("rabbitmq: ListDLQ not implemented in v0.2.0 stub")
}

func (s *Store) Close() error {
	return nil
}

// encode serializes a DomainEvent for RabbitMQ.
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
