package env

import (
	"os"
	"strings"
)

// GetS2SKey devuelve la API key scoped para un servicio, leyendo primero
// S2S_KEY_<SERVICE> y, si está vacía, fallback a S2S_API_KEY.
//
// El nombre de servicio se normaliza: guiones y puntos se convierten a underscores,
// y se pasa a mayúsculas. Ejemplos:
//   - "notification-service" → S2S_KEY_NOTIFICATION_SERVICE
//   - "pim"                  → S2S_KEY_PIM
//   - "catalog.bff"          → S2S_KEY_CATALOG_BFF
//
// Si ambas variables están vacías, devuelve "". El llamador decide si eso es
// error o si el servicio opera sin S2S key (ej. solo JWT).
func GetS2SKey(service string) string {
	if key := os.Getenv(s2sEnvVar(service)); key != "" {
		return key
	}
	return os.Getenv("S2S_API_KEY")
}

// GetS2SKeyOrDefault es como GetS2SKey pero permite un default explícito,
// útil para tests o para entornos locales con keys inseguras documentadas.
func GetS2SKeyOrDefault(service, defaultKey string) string {
	if key := GetS2SKey(service); key != "" {
		return key
	}
	return defaultKey
}

// s2sEnvVar construye el nombre de variable de entorno para la key scoped.
func s2sEnvVar(service string) string {
	normalized := strings.ToUpper(service)
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, ".", "_")
	return "S2S_KEY_" + normalized
}
