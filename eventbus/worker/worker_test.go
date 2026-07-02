package worker

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/hornosg/go-shared/eventbus/application"
	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/infrastructure/memory"
)

func TestWorkerPollOnce(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	config := application.DefaultConfig()
	pub := application.NewPublishUseCase(store, config)
	cons := application.NewConsumeUseCase(store, config)

	var handled bool
	if err := cons.Subscribe("worker.test", func(_ context.Context, _ *domain.DomainEvent) error {
		handled = true
		return nil
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := pub.Publish(ctx, &domain.DomainEvent{EventType: "worker.test"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	w := NewWorker(store, cons, DefaultConfig([]string{"worker.test"}), slog.Default())
	if err := w.PollOnce(ctx); err != nil {
		t.Fatalf("poll once: %v", err)
	}
	if !handled {
		t.Fatal("expected event to be handled")
	}
}

func TestWorkerStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memory.NewStore()
	config := application.DefaultConfig()
	pub := application.NewPublishUseCase(store, config)
	cons := application.NewConsumeUseCase(store, config)

	var handled int
	if err := cons.Subscribe("worker.tick", func(_ context.Context, _ *domain.DomainEvent) error {
		handled++
		return nil
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := pub.Publish(ctx, &domain.DomainEvent{EventType: "worker.tick"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	w := NewWorker(store, cons, Config{PollInterval: 10 * time.Millisecond, MaxConcurrency: 1, EventTypes: []string{"worker.tick"}}, slog.Default())
	w.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	w.Stop()
	if handled == 0 {
		t.Fatal("expected worker to handle at least one event")
	}
}
