// Package worker contains the polling worker that consumes events from the
// EventBus store, dispatches them through the application ConsumeUseCase and
// acks/nacks messages accordingly.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hornosg/go-shared/eventbus/application"
	"github.com/hornosg/go-shared/eventbus/ports"
)

// Config controls the worker poll loop.
type Config struct {
	PollInterval   time.Duration
	MaxConcurrency int
	EventTypes     []string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig(eventTypes []string) Config {
	return Config{
		PollInterval:   5 * time.Second,
		MaxConcurrency: 1,
		EventTypes:     eventTypes,
	}
}

// Worker polls a Store and dispatches events through a ConsumeUseCase.
type Worker struct {
	store    ports.Store
	consumer *application.ConsumeUseCase
	config   Config
	logger   *slog.Logger
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopChan chan struct{}
}

// NewWorker builds a worker.
func NewWorker(store ports.Store, consumer *application.ConsumeUseCase, config Config, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		store:    store,
		consumer: consumer,
		config:   config,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// Start launches the worker goroutine(s).
func (w *Worker) Start(ctx context.Context) {
	for i := 0; i < w.config.MaxConcurrency; i++ {
		w.wg.Add(1)
		go w.loop(ctx)
	}
}

// Stop signals the worker to stop and waits for in-flight messages.
func (w *Worker) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopChan)
	})
	w.wg.Wait()
}

func (w *Worker) loop(ctx context.Context) {
	defer w.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		case <-time.After(w.config.PollInterval):
		}

		for _, eventType := range w.config.EventTypes {
			processed, err := w.consumer.PollOnce(ctx, eventType)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				w.logger.Error("eventbus worker poll failed", "event_type", eventType, "error", err)
				continue
			}
			if processed > 0 {
				w.logger.Debug("eventbus worker processed batch", "event_type", eventType, "count", processed)
			}
		}
	}
}

// PollOnce executes a single poll cycle across all event types. Useful in tests.
func (w *Worker) PollOnce(ctx context.Context) error {
	for _, eventType := range w.config.EventTypes {
		if _, err := w.consumer.PollOnce(ctx, eventType); err != nil {
			return fmt.Errorf("poll %s: %w", eventType, err)
		}
	}
	return nil
}
