package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hornosg/go-shared/eventbus/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreSaveAndPoll(t *testing.T) {
	s := NewStore()
	ctx := context.Background()

	e, err := domain.NewEvent("notification.send", "mc", "t1", "u1", map[string]string{"foo": "bar"})
	require.NoError(t, err)
	require.NoError(t, s.Save(ctx, e))

	polled, err := s.Poll(ctx, "notification.send", 10)
	require.NoError(t, err)
	require.Len(t, polled, 1)
	assert.Equal(t, e.ID, polled[0].ID)
}

func TestStorePollLeasesEvent(t *testing.T) {
	s := NewStore()
	ctx := context.Background()

	e, _ := domain.NewEvent("notification.send", "mc", "t1", "u1", nil)
	s.Save(ctx, e)

	_, err := s.Poll(ctx, "notification.send", 10)
	require.NoError(t, err)

	// Second poll within lease window should return nothing.
	polled, err := s.Poll(ctx, "notification.send", 10)
	require.NoError(t, err)
	assert.Empty(t, polled)
}

func TestStoreMarkProcessed(t *testing.T) {
	s := NewStore()
	ctx := context.Background()

	e, _ := domain.NewEvent("notification.send", "mc", "t1", "u1", nil)
	s.Save(ctx, e)

	polled, _ := s.Poll(ctx, "notification.send", 10)
	require.Len(t, polled, 1)

	require.NoError(t, s.MarkProcessed(ctx, polled[0].ID))
	polled, _ = s.Poll(ctx, "notification.send", 10)
	assert.Empty(t, polled)
}

func TestStoreMarkFailedRetriesThenDLQ(t *testing.T) {
	s := NewStore()
	ctx := context.Background()

	e, _ := domain.NewEvent("notification.send", "mc", "t1", "u1", nil)
	s.Save(ctx, e)

	maxAttempts := 3
	for i := 1; i <= maxAttempts; i++ {
		polled, err := s.Poll(ctx, "notification.send", 10)
		require.NoError(t, err)
		require.Len(t, polled, 1, "attempt %d", i)
		// MarkFailed receives the next attempt number; the store increments internally.
		err = s.MarkFailed(ctx, polled[0].ID, polled[0].Attempt+1, errors.New("boom"), maxAttempts)
		require.NoError(t, err)
		// Force visibility to avoid waiting for exponential backoff in tests.
		s.mu.Lock()
		se := s.events[e.ID]
		if se != nil {
			se.visibleAt = time.Now().UTC().Add(-time.Second)
		}
		s.mu.Unlock()
	}

	// After max attempts the event should be in DLQ and not pollable.
	polled, err := s.Poll(ctx, "notification.send", 10)
	require.NoError(t, err)
	assert.Empty(t, polled)

	dlq, err := s.ListDLQ(ctx, "notification.send", 10)
	require.NoError(t, err)
	require.Len(t, dlq, 1)
	assert.Contains(t, dlq[0].Error, "max attempts exceeded")
}

func TestStoreDelayedEvent(t *testing.T) {
	s := NewStore()
	ctx := context.Background()

	future := time.Now().UTC().Add(5 * time.Minute)
	e, _ := domain.NewEvent("notification.send", "mc", "t1", "u1", nil)
	e.DelayedUntil = &future
	s.Save(ctx, e)

	polled, err := s.Poll(ctx, "notification.send", 10)
	require.NoError(t, err)
	assert.Empty(t, polled)
}

func TestStoreDLQFilter(t *testing.T) {
	s := NewStore()
	ctx := context.Background()

	e1, _ := domain.NewEvent("notification.send", "mc", "t1", "u1", nil)
	e2, _ := domain.NewEvent("other.event", "mc", "t1", "u1", nil)
	s.Save(ctx, e1)
	s.Save(ctx, e2)
	s.MarkFailed(ctx, e1.ID, 1, errors.New("boom"), 1)
	s.MarkFailed(ctx, e2.ID, 1, errors.New("boom"), 1)

	filtered, err := s.ListDLQ(ctx, "notification.send", 10)
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "notification.send", filtered[0].EventType)
}
