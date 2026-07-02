package ports

import (
	"context"

	"github.com/hornosg/go-shared/eventbus/domain"
)

// Publisher pushes DomainEvents to a backing store / topic / queue.
type Publisher interface {
	Publish(ctx context.Context, event *domain.DomainEvent) error
	PublishBatch(ctx context.Context, events []*domain.DomainEvent) error
	Close() error
}

// HandlerFunc processes a consumed DomainEvent. Returning a non-nil error signals
// the consumer that the event should be retried (unless retries are exhausted).
type HandlerFunc func(ctx context.Context, event *domain.DomainEvent) error

// Consumer receives DomainEvents from a backing store and dispatches them to handlers.
type Consumer interface {
	Subscribe(eventType string, handler HandlerFunc) error
	Run(ctx context.Context) error
	Close() error
}

// Store is the persistence abstraction used by adapters that need durable storage
// (memory, PostgreSQL, Redis streams, etc.). It is separate from Publisher/Consumer
// so a single adapter can expose both semantics.
type Store interface {
	Save(ctx context.Context, event *domain.DomainEvent) error
	SaveBatch(ctx context.Context, events []*domain.DomainEvent) error
	// Poll returns events that are visible for consumption, limited by batchSize.
	// Implementations must respect delayed visibility and ownership/lease.
	Poll(ctx context.Context, eventType string, batchSize int) ([]*domain.DomainEvent, error)
	// MarkProcessed deletes or archives a successfully consumed event.
	MarkProcessed(ctx context.Context, eventID string) error
	// MarkFailed updates attempt count and error; if maxAttempts exceeded, moves to DLQ.
	MarkFailed(ctx context.Context, eventID string, attempt int, err error, maxAttempts int) error
	// DLQ events that exceeded retries.
	MoveToDLQ(ctx context.Context, event *domain.DomainEvent, reason string) error
	// ListDLQ returns dead-letter events optionally filtered by eventType.
	ListDLQ(ctx context.Context, eventType string, limit int) ([]*domain.DomainEvent, error)
}
