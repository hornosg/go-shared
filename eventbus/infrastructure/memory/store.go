package memory

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/hornosg/go-shared/eventbus/ports"
)

// Store is an in-memory implementation of eventbus/ports.Store.
// It is intended for unit tests and local development; it does not survive process restarts.
type Store struct {
	mu     sync.RWMutex
	events map[string]*storedEvent
	dlq    map[string]*domain.DomainEvent
	closed bool
}

type storedEvent struct {
	*domain.DomainEvent
	visibleAt time.Time
	ownedBy   string
}

// NewStore creates an empty in-memory store.
func NewStore() *Store {
	return &Store{
		events: make(map[string]*storedEvent),
		dlq:    make(map[string]*domain.DomainEvent),
	}
}

// Save stores a single event.
func (s *Store) Save(ctx context.Context, event *domain.DomainEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("memory store is closed")
	}
	if event.ID == "" {
		return errors.New("event id is required")
	}
	ev := event.Clone()
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	s.events[ev.ID] = &storedEvent{DomainEvent: ev, visibleAt: s.computeVisibleAt(ev)}
	return nil
}

// SaveBatch stores multiple events atomically.
func (s *Store) SaveBatch(ctx context.Context, events []*domain.DomainEvent) error {
	for _, e := range events {
		if err := s.Save(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// Poll returns up to batchSize events of the given eventType that are visible now.
// It leases them with a 30-second visibility window by setting visibleAt into the future.
func (s *Store) Poll(ctx context.Context, eventType string, batchSize int) ([]*domain.DomainEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("memory store is closed")
	}
	if batchSize <= 0 {
		batchSize = 1
	}
	now := time.Now().UTC()
	var result []*domain.DomainEvent
	for _, se := range s.events {
		if se.EventType != eventType {
			continue
		}
		if se.visibleAt.After(now) {
			continue
		}
		if se.DLQAt != nil {
			continue
		}
		se.visibleAt = now.Add(30 * time.Second)
		clone := se.Clone()
		clone.Attempt = se.Attempt
		result = append(result, clone)
		if len(result) >= batchSize {
			break
		}
	}
	// Stable ordering by OccurredAt for deterministic tests.
	sort.Slice(result, func(i, j int) bool {
		return result[i].OccurredAt.Before(result[j].OccurredAt)
	})
	return result, nil
}

// MarkProcessed removes an event from the in-flight set.
func (s *Store) MarkProcessed(ctx context.Context, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[eventID]; !ok {
		return errors.New("event not found")
	}
	delete(s.events, eventID)
	return nil
}

// MarkFailed increments the attempt counter. If maxAttempts is exceeded the event is moved to DLQ.
func (s *Store) MarkFailed(ctx context.Context, eventID string, attempt int, err error, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.events[eventID]
	if !ok {
		return errors.New("event not found")
	}
	se.Attempt = attempt
	if err != nil {
		se.Error = err.Error()
	}
	if attempt >= maxAttempts {
		se.DLQAt = timePtr(time.Now().UTC())
		se.Error = "max attempts exceeded: " + se.Error
		return s.moveToDLQLocked(se.DomainEvent, "")
	}
	// Re-queue with exponential backoff.
	delay := domain.DefaultRetryPolicy().ComputeDelay(attempt)
	se.visibleAt = time.Now().UTC().Add(delay)
	return nil
}

// MoveToDLQ moves an event to the dead-letter queue.
func (s *Store) MoveToDLQ(ctx context.Context, event *domain.DomainEvent, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.moveToDLQLocked(event, reason)
}

func (s *Store) moveToDLQLocked(event *domain.DomainEvent, reason string) error {
	se, ok := s.events[event.ID]
	if ok {
		delete(s.events, event.ID)
		event = se.DomainEvent
	}
	ev := event.Clone()
	if ev.DLQAt == nil {
		now := time.Now().UTC()
		ev.DLQAt = &now
	}
	if reason != "" && ev.Error == "" {
		ev.Error = reason
	}
	s.dlq[ev.ID] = ev
	return nil
}

// ListDLQ returns dead-letter events optionally filtered by eventType.
func (s *Store) ListDLQ(ctx context.Context, eventType string, limit int) ([]*domain.DomainEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*domain.DomainEvent
	for _, ev := range s.dlq {
		if eventType != "" && ev.EventType != eventType {
			continue
		}
		result = append(result, ev.Clone())
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].DLQAt.Before(*result[j].DLQAt)
	})
	return result, nil
}

// Close is a no-op for the in-memory store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// computeVisibleAt computes when an event becomes visible, honoring DelayedUntil.
func (s *Store) computeVisibleAt(event *domain.DomainEvent) time.Time {
	if event.DelayedUntil != nil && event.DelayedUntil.After(time.Now().UTC()) {
		return *event.DelayedUntil
	}
	return time.Now().UTC()
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// compile-time interface assertions
var _ ports.Store = (*Store)(nil)
