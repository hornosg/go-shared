// Package application contains the EventBus use cases: publish, consume, retry, DLQ.
package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	sharedport "github.com/hornosg/go-shared/domain/port"
	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/metrics"
	"github.com/hornosg/go-shared/eventbus/ports"
)

// Config controls retry / DLQ / metric behaviour.
type Config struct {
	MaxRetries      int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	BackoffFactor   float64
	DLQTopicSuffix  string
	MetricsRecorder sharedport.MetricsRecorder // optional
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     60 * time.Second,
		BackoffFactor:  2.0,
		DLQTopicSuffix: ".dlq",
	}
}

// PublishUseCase publishes DomainEvents to the configured Store and records metrics.
type PublishUseCase struct {
	store   ports.Store
	config  Config
	metrics *metrics.EventBusRecorder
}

// NewPublishUseCase builds a publisher backed by store.
func NewPublishUseCase(store ports.Store, config Config) *PublishUseCase {
	return &PublishUseCase{
		store:   store,
		config:  config,
		metrics: metrics.NewEventBusRecorder(config.MetricsRecorder),
	}
}

// Publish stores a single domain event in the backing store.
func (uc *PublishUseCase) Publish(ctx context.Context, event *domain.DomainEvent) error {
	if event == nil {
		return errors.New("eventbus: event is nil")
	}
	if event.EventType == "" {
		return errors.New("eventbus: event type is required")
	}
	if event.ID == "" {
		event.ID = domain.GenerateID()
	}
	if event.Version == "" {
		event.Version = "1"
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}

	channel := event.Channel
	if channel == "" {
		channel = event.EventType
	}

	start := time.Now()
	err := uc.store.Save(ctx, event)
	if err != nil {
		uc.metrics.Failed(channel, event.EventType, "publish_store_error")
		return fmt.Errorf("eventbus: publish %s: %w", event.EventType, err)
	}

	uc.metrics.PublishTime(channel, event.EventType, float64(time.Since(start).Milliseconds()))
	uc.metrics.Published(channel, event.EventType)
	return nil
}

// PublishBatch stores multiple domain events atomically (best-effort, adapter-dependent).
func (uc *PublishUseCase) PublishBatch(ctx context.Context, events []*domain.DomainEvent) error {
	if len(events) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for _, e := range events {
		if e == nil {
			continue
		}
		if e.ID == "" {
			e.ID = domain.GenerateID()
		}
		if e.Version == "" {
			e.Version = "1"
		}
		if e.OccurredAt.IsZero() {
			e.OccurredAt = now
		}
	}

	start := time.Now()
	err := uc.store.SaveBatch(ctx, events)
	if err != nil {
		uc.metrics.Failed("batch", "batch", "publish_batch_store_error")
		return fmt.Errorf("eventbus: publish batch: %w", err)
	}

	uc.metrics.PublishTime("batch", "batch", float64(time.Since(start).Milliseconds()))
	for _, e := range events {
		channel := e.Channel
		if channel == "" {
			channel = e.EventType
		}
		uc.metrics.Published(channel, e.EventType)
	}
	return nil
}

// handlerRegistry keeps per-event-type handlers.
type handlerRegistry struct {
	handlers map[string][]ports.HandlerFunc
}

func newHandlerRegistry() *handlerRegistry {
	return &handlerRegistry{handlers: make(map[string][]ports.HandlerFunc)}
}

func (r *handlerRegistry) register(eventType string, h ports.HandlerFunc) error {
	if eventType == "" {
		return errors.New("eventbus: event type is required")
	}
	if h == nil {
		return errors.New("eventbus: handler is nil")
	}
	r.handlers[eventType] = append(r.handlers[eventType], h)
	return nil
}

func (r *handlerRegistry) dispatch(ctx context.Context, event *domain.DomainEvent) error {
	list, ok := r.handlers[event.EventType]
	if !ok || len(list) == 0 {
		return nil
	}
	var firstErr error
	for _, h := range list {
		if err := h(ctx, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ConsumeUseCase polls events from the Store and dispatches them to registered handlers.
type ConsumeUseCase struct {
	store    ports.Store
	config   Config
	metrics  *metrics.EventBusRecorder
	registry *handlerRegistry
}

// NewConsumeUseCase builds a consumer.
func NewConsumeUseCase(store ports.Store, config Config) *ConsumeUseCase {
	return &ConsumeUseCase{
		store:    store,
		config:   config,
		metrics:  metrics.NewEventBusRecorder(config.MetricsRecorder),
		registry: newHandlerRegistry(),
	}
}

// Subscribe registers a handler for an event type.
func (uc *ConsumeUseCase) Subscribe(eventType string, handler ports.HandlerFunc) error {
	return uc.registry.register(eventType, handler)
}

// PollOnce fetches a batch of events of the given type, dispatches them and acks/nacks.
// It returns the number of events processed.
func (uc *ConsumeUseCase) PollOnce(ctx context.Context, eventType string) (int, error) {
	events, err := uc.store.Poll(ctx, eventType, 10)
	if err != nil {
		return 0, fmt.Errorf("eventbus: poll %s: %w", eventType, err)
	}
	if len(events) == 0 {
		return 0, nil
	}

	processed := 0
	for _, event := range events {
		channel := event.Channel
		if channel == "" {
			channel = event.EventType
		}

		start := time.Now()
		err := uc.registry.dispatch(ctx, event)
		uc.metrics.ConsumeTime(channel, event.EventType, float64(time.Since(start).Milliseconds()))

		if err == nil {
			if ackErr := uc.store.MarkProcessed(ctx, event.ID); ackErr != nil {
				uc.metrics.Failed(channel, event.EventType, "ack_error")
				return processed, fmt.Errorf("eventbus: ack %s: %w", event.ID, ackErr)
			}
			uc.metrics.Consumed(channel, event.EventType)
			processed++
			continue
		}

		// retry / DLQ logic
		attempt := event.Attempt + 1
		if attempt >= uc.config.MaxRetries {
			dlqErr := uc.store.MarkFailed(ctx, event.ID, attempt, err, uc.config.MaxRetries)
			if dlqErr == nil {
				uc.metrics.DLQ(channel, event.EventType)
			}
		} else {
			markErr := uc.store.MarkFailed(ctx, event.ID, attempt, err, uc.config.MaxRetries)
			if markErr == nil {
				uc.metrics.Retried(channel, event.EventType, attempt)
			}
		}
		uc.metrics.Failed(channel, event.EventType, "handler_error")
	}

	return processed, nil
}
