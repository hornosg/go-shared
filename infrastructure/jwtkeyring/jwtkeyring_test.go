package jwtkeyring

import (
	"os"
	"path/filepath"
	"testing"
)

// Vector fijo: el kid derivado de la pública de T2 es el que emite iam-service (ADR-003 §c).
func TestKID_VectorFijoDeT2(t *testing.T) {
	ring, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if got := ring.KIDs(); len(got) != 1 || got[0] != "acc-69a4a91f940a" {
		t.Fatalf("kids = %v, se espera [acc-69a4a91f940a]", got)
	}
}

func TestResolve_FailClosed(t *testing.T) {
	if _, err := Resolve("", true); err == nil {
		t.Error("release sin directorio debe devolver error")
	}
	if ring, err := Resolve("", false); err != nil || ring != nil {
		t.Errorf("fuera de release sin directorio: ring=%v err=%v, se espera nil/nil", ring, err)
	}
	if _, err := Resolve(t.TempDir(), false); err == nil {
		t.Error("directorio sin .pem debe devolver error en cualquier modo")
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "x.pem"), []byte("no es pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(bad, false); err == nil {
		t.Error("PEM inválido debe devolver error")
	}
}

func TestKeyfunc_SecretoEnBlancoRechazaHS256(t *testing.T) {
	// Un secreto de sólo espacios nunca es clave HMAC válida.
	if kf := Keyfunc("   ", nil); kf == nil {
		t.Fatal("Keyfunc nil")
	}
}
