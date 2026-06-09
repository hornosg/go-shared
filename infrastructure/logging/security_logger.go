package logging

import (
	"encoding/json"
	"io"
	"os"
	"time"

	sharedport "github.com/mercadocercano/go-shared/domain/port"
)

// canonicalLine is the single JSON log line emitted per security event.
// Field names are fixed — Grafana/Loki dashboards and alerts reference them directly.
type canonicalLine struct {
	Timestamp      string `json:"ts"`
	Level          string `json:"level"`
	Service        string `json:"service"`
	Event          string `json:"event"`
	UserID         string `json:"user_id,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	Email          string `json:"email,omitempty"`
	IP             string `json:"ip,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope,omitempty"`
	JWTTenantID    string `json:"jwt_tenant_id,omitempty"`
	HeaderTenantID string `json:"header_tenant_id,omitempty"`
}

func levelFor(e sharedport.EventType) string {
	switch e {
	case sharedport.EventLoginFailed:
		return "warn"
	case sharedport.EventTenantMismatch:
		return "error"
	default:
		return "info"
	}
}

// SecurityLogger writes one canonical JSON line per event to an io.Writer (default: stdout).
// Loki scrapes stdout in the cluster; the service label comes from the Promtail/Alloy config.
type SecurityLogger struct {
	writer  io.Writer
	service string
}

func NewSecurityLogger(service string) *SecurityLogger {
	return &SecurityLogger{writer: os.Stdout, service: service}
}

func NewSecurityLoggerWithWriter(service string, w io.Writer) *SecurityLogger {
	return &SecurityLogger{writer: w, service: service}
}

func (l *SecurityLogger) Log(event sharedport.SecurityEvent) {
	line := canonicalLine{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Level:          levelFor(event.Event),
		Service:        l.service,
		Event:          string(event.Event),
		UserID:         event.UserID,
		TenantID:       event.TenantID,
		Email:          event.Email,
		IP:             event.IPAddress,
		UserAgent:      event.UserAgent,
		Reason:         event.Reason,
		Scope:          event.Scope,
		JWTTenantID:    event.JWTTenantID,
		HeaderTenantID: event.HeaderTenantID,
	}
	data, err := json.Marshal(line)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = l.writer.Write(data)
}
