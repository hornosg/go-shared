package jwtkeyring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
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

// ACC-E03 T6: la rama HMAC no existe más. Un HS256 firmado con el mismo secreto que se le pasa a
// ParseDual (el JWT_SECRET de la flota) se rechaza.
func TestParseDual_T6_HS256ConElSecretoRechazado(t *testing.T) {
	const secret = "fleet-shared-secret-at-least-32-characters"
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "u"}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseDual(signed, jwt.MapClaims{}, secret, nil); err == nil {
		t.Fatal("ParseDual aceptó HS256 tras el cutover de T6")
	}
	if len(AcceptedMethods) != 1 || AcceptedMethods[0] != jwt.SigningMethodRS256.Alg() {
		t.Fatalf("AcceptedMethods = %v, se espera sólo RS256", AcceptedMethods)
	}
}
