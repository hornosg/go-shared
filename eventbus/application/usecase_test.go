package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/infrastructure/memory"
)

func TestPublishUseCase_Publish(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	uc := NewPublishUseCase(store, DefaultConfig())

	evt := &domain.DomainEvent{EventType: "test.event"}
	if err := uc.Publish(ctx, evt); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if evt.ID == "" {
		t.Fatal("expected event ID to be generated")
	}
}

func TestPublishUseCase_PublishBatch(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	uc := NewPublishUseCase(store, DefaultConfig())

	events := []*domain.DomainEvent{
		{EventType: "a"},
		{EventType: "b"},
	}
	if err := uc.PublishBatch(ctx, events); err != nil {
		t.Fatalf("publish batch: %v", err)
	}
}

func TestConsumeUseCase_SubscribeAndPoll(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	config := DefaultConfig()
	pub := NewPublishUseCase(store, config)
	cons := NewConsumeUseCase(store, config)

	var received bool
	if err := cons.Subscribe("order.created", func(_ context.Context, _ *domain.DomainEvent) error {
		received = true
		return nil
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := pub.Publish(ctx, &domain.DomainEvent{EventType: "order.created"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	processed, err := cons.PollOnce(ctx, "order.created")
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if processed != 1 || !received {
		t.Fatalf("expected 1 processed event, got %d (received=%v)", processed, received)
	}
}

func TestConsumeUseCase_RetryThenDLQ(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	config := Config{MaxRetries: 1, InitialBackoff: 1 * time.Millisecond, MaxBackoff: 5 * time.Millisecond, BackoffFactor: 1}
	pub := NewPublishUseCase(store, config)
	cons := NewConsumeUseCase(store, config)

	fails := 0
	if err := cons.Subscribe("fails", func(_ context.Context, _ *domain.DomainEvent) error {
		fails++
		return errors.New("handler error")
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := pub.Publish(ctx, &domain.DomainEvent{EventType: "fails"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	_, _ = cons.PollOnce(ctx, "fails")

	dlq, err := store.ListDLQ(ctx, "fails", 10)
	if err != nil {
		t.Fatalf("list dlq: %v", err)
	}
	if len(dlq) != 1 {
		t.Fatalf("expected 1 dlq event, got %d (fails=%d)", len(dlq), fails)
	}
}
