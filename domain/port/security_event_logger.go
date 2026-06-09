package port

// EventType identifies a security event. Convention: <domain>.<action>_<result>, lowercase, dot-separated.
type EventType string

const (
	EventLoginSuccess   EventType = "auth.login_success"
	EventLoginFailed    EventType = "auth.login_failed"
	EventLogout         EventType = "auth.logout"
	EventTokenRevoked   EventType = "auth.token_revoked"
	EventTenantMismatch EventType = "auth.tenant_mismatch"
)

// SecurityEvent is the canonical payload for all security-relevant log entries.
// All fields except Event are optional; zero values are omitted by the adapter.
type SecurityEvent struct {
	Event          EventType
	UserID         string
	TenantID       string
	Email          string
	IPAddress      string
	UserAgent      string
	Reason         string
	Scope          string
	JWTTenantID    string
	HeaderTenantID string
}

// SecurityEventLogger is the port for emitting security events.
// Application-layer code depends on this interface; adapters (stdout JSON, Loki push, etc.) implement it.
type SecurityEventLogger interface {
	Log(event SecurityEvent)
}
