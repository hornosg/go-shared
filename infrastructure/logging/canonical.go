package logging

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

// CanonicalLogger emite una línea JSON canónica por evento de dominio, según ADR-001.
// Envelope fijo: ts (RFC3339 UTC) / level / service / event. Los campos de dominio
// se agregan flat (no anidados) y los vacíos se omiten.
//
// Es el primitivo genérico que cualquier dominio puede envolver con un puerto + struct
// tipado (ver SecurityLogger para el caso de seguridad / ADR-001a). Los nombres de campo
// comunes (user_id, tenant_id, ip) DEBEN ser idénticos entre dominios y servicios para
// que el LogQL cross-service funcione.
type CanonicalLogger struct {
	writer  io.Writer
	service string
}

// NewCanonicalLogger crea un logger que escribe a stdout. El service se fija en
// construcción y nunca se pasa por llamada.
func NewCanonicalLogger(service string) *CanonicalLogger {
	return &CanonicalLogger{writer: os.Stdout, service: service}
}

// NewCanonicalLoggerWithWriter permite inyectar un io.Writer (tests: bytes.Buffer / io.Discard).
func NewCanonicalLoggerWithWriter(service string, w io.Writer) *CanonicalLogger {
	return &CanonicalLogger{writer: w, service: service}
}

// Emit escribe UNA línea JSON: ts/level/service/event + campos de dominio flat (omitempty).
// Las claves reservadas del envelope no pueden ser pisadas por fields.
func (l *CanonicalLogger) Emit(level, event string, fields map[string]any) {
	line := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"level":   level,
		"service": l.service,
		"event":   event,
	}
	for k, v := range fields {
		switch k {
		case "ts", "level", "service", "event":
			continue // no permitir override del envelope
		}
		if v == nil || v == "" {
			continue // omitempty
		}
		line[k] = v
	}
	data, err := json.Marshal(line)
	if err != nil {
		return
	}
	_, _ = l.writer.Write(append(data, '\n'))
}
