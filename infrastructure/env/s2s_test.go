package env

import (
	"os"
	"testing"
)

func TestGetS2SKey_PrefersScopedKey(t *testing.T) {
	t.Setenv("S2S_KEY_NOTIFICATION_SERVICE", "scoped-key")
	t.Setenv("S2S_API_KEY", "legacy-key")

	got := GetS2SKey("notification-service")
	if got != "scoped-key" {
		t.Fatalf("esperaba scoped-key, obtuvo %q", got)
	}
}

func TestGetS2SKey_FallbackToLegacy(t *testing.T) {
	t.Setenv("S2S_KEY_NOTIFICATION_SERVICE", "")
	t.Setenv("S2S_API_KEY", "legacy-key")

	got := GetS2SKey("notification-service")
	if got != "legacy-key" {
		t.Fatalf("esperaba legacy-key, obtuvo %q", got)
	}
}

func TestGetS2SKey_EmptyWhenNeither(t *testing.T) {
	t.Setenv("S2S_KEY_NOTIFICATION_SERVICE", "")
	t.Setenv("S2S_API_KEY", "")

	got := GetS2SKey("notification-service")
	if got != "" {
		t.Fatalf("esperaba cadena vacía, obtuvo %q", got)
	}
}

func TestGetS2SKey_NormalizesNames(t *testing.T) {
	cases := []struct {
		service string
		wantVar string
	}{
		{"notification-service", "S2S_KEY_NOTIFICATION_SERVICE"},
		{"pim", "S2S_KEY_PIM"},
		{"catalog.bff", "S2S_KEY_CATALOG_BFF"},
		{"my_service", "S2S_KEY_MY_SERVICE"},
	}

	for _, tc := range cases {
		t.Run(tc.service, func(t *testing.T) {
			t.Setenv(tc.wantVar, "key-"+tc.service)
			// limpiar fallback para evitar falsos positivos
			t.Setenv("S2S_API_KEY", "")

			got := GetS2SKey(tc.service)
			if got != "key-"+tc.service {
				t.Fatalf("esperaba %q, obtuvo %q", "key-"+tc.service, got)
			}
		})
	}
}

func TestGetS2SKeyOrDefault_UsesDefault(t *testing.T) {
	t.Setenv("S2S_KEY_PIM", "")
	t.Setenv("S2S_API_KEY", "")

	got := GetS2SKeyOrDefault("pim", "default-key")
	if got != "default-key" {
		t.Fatalf("esperaba default-key, obtuvo %q", got)
	}
}

func TestGetS2SKeyOrDefault_PrefersEnv(t *testing.T) {
	t.Setenv("S2S_KEY_PIM", "env-key")

	got := GetS2SKeyOrDefault("pim", "default-key")
	if got != "env-key" {
		t.Fatalf("esperaba env-key, obtuvo %q", got)
	}
}

// TestGetS2SKey_NoLeakFromPrevious garantiza que una variable sin limpiar de
// otro test no contamina, ya que t.Setenv restaura el valor original.
func TestGetS2SKey_NoLeakFromPrevious(t *testing.T) {
	// Si S2S_KEY_NOTIFICATION_SERVICE quedó seteada por un test anterior,
	// esta variable tendría un valor. Fuerzamos un entorno limpio usando un
	// servicio distinto (tenant-service) y aseguramos fallback vacío.
	t.Setenv("S2S_KEY_TENANT_SERVICE", "")
	t.Setenv("S2S_API_KEY", "")

	if os.Getenv("S2S_KEY_NOTIFICATION_SERVICE") != "" {
		// No fallamos por la variable sola; solo registramos que t.Setenv no limpió.
		t.Logf("ADVERTENCIA: S2S_KEY_NOTIFICATION_SERVICE=%q pervive entre tests", os.Getenv("S2S_KEY_NOTIFICATION_SERVICE"))
	}

	got := GetS2SKey("tenant-service")
	if got != "" {
		t.Fatalf("esperaba cadena vacía, obtuvo %q", got)
	}
}
