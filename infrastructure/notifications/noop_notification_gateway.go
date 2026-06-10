package notifications

import (
	"context"

	"github.com/hornosg/go-shared/domain/port"
)

// NoopNotificationGateway discards all notifications silently.
// Use in tests or when the notifications-service is not yet configured.
type NoopNotificationGateway struct{}

func NewNoopNotificationGateway() *NoopNotificationGateway {
	return &NoopNotificationGateway{}
}

func (g *NoopNotificationGateway) Send(_ context.Context, n port.Notification) (*port.NotificationResult, error) {
	return &port.NotificationResult{Channel: n.Channel, Status: "queued", MessageID: "noop"}, nil
}

func (g *NoopNotificationGateway) SendBatch(_ context.Context, notifications []port.Notification) ([]port.NotificationResult, error) {
	results := make([]port.NotificationResult, len(notifications))
	for i, n := range notifications {
		results[i] = port.NotificationResult{Channel: n.Channel, Status: "queued", MessageID: "noop"}
	}
	return results, nil
}
