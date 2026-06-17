package logging_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/hornosg/go-shared/infrastructure/logging"
)

func TestCanonicalLogger_EmitEnvelopeAndFlatFields(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewCanonicalLoggerWithWriter("orders", &buf)

	l.Emit("warn", "orders.checkout_failed", map[string]any{
		"tenant_id": "t-1",
		"reason":    "out_of_stock",
		"empty":     "", // omitempty: no debe aparecer
	})

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("se esperaba 1 línea, hubo %d", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal(lines[0], &m); err != nil {
		t.Fatalf("línea no es JSON válido: %v", err)
	}

	if m["service"] != "orders" || m["level"] != "warn" || m["event"] != "orders.checkout_failed" {
		t.Errorf("envelope incorrecto: %v", m)
	}
	if m["ts"] == nil || m["ts"] == "" {
		t.Error("ts (RFC3339 UTC) debe estar presente")
	}
	if m["tenant_id"] != "t-1" || m["reason"] != "out_of_stock" {
		t.Errorf("campos de dominio incorrectos: %v", m)
	}
	if _, ok := m["empty"]; ok {
		t.Error("los campos vacíos deben omitirse (omitempty)")
	}
}

func TestCanonicalLogger_EnvelopeKeysCannotBeOverridden(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewCanonicalLoggerWithWriter("orders", &buf)

	// fields intenta pisar service/event/level/ts — debe ignorarse.
	l.Emit("info", "orders.ok", map[string]any{"service": "hacked", "event": "evil"})

	var m map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m)
	if m["service"] != "orders" || m["event"] != "orders.ok" {
		t.Errorf("el envelope no debe poder ser pisado por fields: %v", m)
	}
}
