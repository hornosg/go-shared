package port

import "context"

// Channel identifies the delivery medium for a notification.
type Channel string

const (
	ChannelEmail    Channel = "email"
	ChannelSMS      Channel = "sms"
	ChannelWhatsApp Channel = "whatsapp"
	ChannelTelegram Channel = "telegram"
	ChannelPush     Channel = "push"
	ChannelWebhook  Channel = "webhook"
)

// Notification is the canonical payload sent to the notifications-service.
// Services may embed this in their own envelope types for domain-specific helpers.
type Notification struct {
	// Channel is the delivery medium.
	Channel Channel `json:"channel"`

	// Recipient is the address for the chosen channel:
	// email address, E.164 phone number, chat_id, webhook URL, etc.
	Recipient string `json:"recipient"`

	// Subject is optional and only meaningful for email.
	Subject string `json:"subject,omitempty"`

	// TemplateID references a template in the notifications-service.
	// When set, Body is used as fallback only.
	TemplateID string `json:"template_id,omitempty"`

	// Body is the plain-text or HTML body. Used when TemplateID is empty.
	Body string `json:"body,omitempty"`

	// Data holds template variables or extra payload for the channel.
	Data map[string]any `json:"data,omitempty"`

	// Metadata carries correlation headers: tenant_id, correlation_id, source, etc.
	// Not delivered to the recipient; used for tracing and routing.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NotificationResult is returned by the gateway after a delivery attempt.
type NotificationResult struct {
	MessageID string  `json:"message_id"`
	Channel   Channel `json:"channel"`
	// Status is one of "sent", "queued", "failed".
	Status string `json:"status"`
	// Err is populated when Status == "failed".
	Err string `json:"error,omitempty"`
}

// NotificationGateway is the port for dispatching notifications through
// the notifications-service regardless of the delivery channel.
//
// Projects that need domain-specific helpers (e.g. SendWelcomeEmail, AlertLowStock)
// should define their own wrapper/facade that calls Send internally rather than
// extending this interface.
type NotificationGateway interface {
	Send(ctx context.Context, n Notification) (*NotificationResult, error)
	SendBatch(ctx context.Context, notifications []Notification) ([]NotificationResult, error)
}
