// Package sqs contains the SQS adapter stub for the platform EventBus.
// It exposes the ports.Store interface and leaves the AWS SDK wiring to the
// consumer (environment credentials, endpoint, region, etc.).
package sqs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/ports"
)

// Config holds the SQS-specific connection parameters.
// Secrets must be injected via environment / Vault, never hardcoded.
type Config struct {
	Region            string
	QueueURL          string // full queue URL; used as topic name
	Endpoint          string // optional, for localstack
	AttributeNames    []string
	MaxMessages       int    // max 10
	WaitTimeSeconds   int    // long polling in seconds
	VisibilityTimeout time.Duration
}

// Store implements ports.Store on top of Amazon SQS.
// The AWS SDK client is stored as interface{} to avoid forcing an SDK dependency
// on consumers that only compile the memory adapter.
type Store struct {
	config Config
	client any // *sqs.SQS when compiled with AWS SDK
}

// NewStore creates a store backed by SQS.
// The caller must provide an initialized AWS SQS client.
func NewStore(config Config, client any) *Store {
	return &Store{config: config, client: client}
}

func (s *Store) Save(ctx context.Context, event *domain.DomainEvent) error {
	if s.client == nil {
		return errors.New("sqs: client not configured")
	}
	if event == nil || event.EventType == "" {
		return errors.New("sqs: event type is required")
	}
	_ = ctx
	return fmt.Errorf("sqs: Save not implemented in v0.2.0 stub")
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
		return nil, errors.New("sqs: client not configured")
	}
	_ = ctx
	_ = eventType
	_ = batchSize
	return nil, fmt.Errorf("sqs: Poll not implemented in v0.2.0 stub")
}

func (s *Store) MarkProcessed(ctx context.Context, eventID string) error {
	if s.client == nil {
		return errors.New("sqs: client not configured")
	}
	_ = ctx
	_ = eventID
	return fmt.Errorf("sqs: MarkProcessed not implemented in v0.2.0 stub")
}

func (s *Store) MarkFailed(ctx context.Context, eventID string, attempt int, err error, maxAttempts int) error {
	if s.client == nil {
		return errors.New("sqs: client not configured")
	}
	_ = ctx
	_ = eventID
	_ = attempt
	_ = err
	_ = maxAttempts
	return fmt.Errorf("sqs: MarkFailed not implemented in v0.2.0 stub")
}

func (s *Store) MoveToDLQ(ctx context.Context, event *domain.DomainEvent, reason string) error {
	if s.client == nil {
		return errors.New("sqs: client not configured")
	}
	_ = ctx
	_ = event
	_ = reason
	return fmt.Errorf("sqs: MoveToDLQ not implemented in v0.2.0 stub")
}

func (s *Store) ListDLQ(ctx context.Context, eventType string, limit int) ([]*domain.DomainEvent, error) {
	if s.client == nil {
		return nil, errors.New("sqs: client not configured")
	}
	_ = ctx
	_ = eventType
	_ = limit
	return nil, fmt.Errorf("sqs: ListDLQ not implemented in v0.2.0 stub")
}

func (s *Store) Close() error {
	return nil
}

// encode serializes a DomainEvent to a JSON body for SQS.
func encode(event *domain.DomainEvent) ([]byte, error) {
	return json.Marshal(map[string]any{
		"id":         event.ID,
		"event_type": event.EventType,
		"payload":    string(event.Payload),
		"metadata": map[string]string{
			"channel":    event.Channel,
			"namespace":  event.Namespace,
			"tenant_id":  event.TenantID,
			"version":    event.Version,
			"occurred_at": event.OccurredAt.Format(time.RFC3339Nano),
		},
	})
}

var _ ports.Store = (*Store)(nil)
