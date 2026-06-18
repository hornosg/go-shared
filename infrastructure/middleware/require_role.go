package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// RequireRole devuelve un middleware Gin que exige que el token traiga al menos uno de
// los roles indicados (claim `roles`). Debe ejecutarse DESPUÉS de TenantValidation, que
// es quien deja `jwt_claims` en el contexto.
//
// Es FAIL-CLOSED: si no hay claims en contexto (p. ej. un ExcludedRoute mal configurado
// o el bypass de tenant abierto) responde 403 — defensa en profundidad para que un error
// de cableado nunca abra un endpoint protegido. Devuelve 403 (no 401): el usuario está
// autenticado, solo no autorizado.
func RequireRole(allowed ...string) gin.HandlerFunc {
	allowedSet := toSet(allowed)
	return func(c *gin.Context) {
		roles, ok := rolesFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden: missing authorization context"})
			return
		}
		for _, r := range roles {
			if _, hit := allowedSet[r]; hit {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden: missing required role"})
	}
}

// RequirePermission exige al menos uno de los permisos finos (claim `perms`). El permiso
// comodín "*" en el token concede cualquier permiso (roles admin).
//
// ADVERTENCIA DE SEGURIDAD (condición C3): NO usar RequirePermission para proteger
// acciones de separación de funciones como la aprobación de descuadres de caja
// (`sales:cash_session:approve_review`). El comodín "*" de un admin pasaría ese chequeo y
// rompería la separación cajero/supervisor. Esas acciones deben protegerse con
// RequireRole("supervisor") EXACTO, donde el comodín no aplica.
func RequirePermission(allowed ...string) gin.HandlerFunc {
	allowedSet := toSet(allowed)
	return func(c *gin.Context) {
		claims, ok := claimsFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden: missing authorization context"})
			return
		}
		perms := stringSliceClaim(claims, "perms")
		for _, p := range perms {
			if p == "*" {
				c.Next()
				return
			}
			if _, hit := allowedSet[p]; hit {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden: missing required permission"})
	}
}

// rolesFromContext obtiene los roles del request. Prefiere la clave "roles" que setea
// TenantValidation; si no está, los deriva de "jwt_claims" (tolerante a ambos formatos).
func rolesFromContext(c *gin.Context) ([]string, bool) {
	if v, exists := c.Get("roles"); exists {
		if roles, ok := v.([]string); ok {
			return roles, true
		}
	}
	claims, ok := claimsFromContext(c)
	if !ok {
		return nil, false
	}
	return stringSliceClaim(claims, "roles"), true
}

func claimsFromContext(c *gin.Context) (jwt.MapClaims, bool) {
	v, exists := c.Get("jwt_claims")
	if !exists {
		return nil, false
	}
	claims, ok := v.(jwt.MapClaims)
	return claims, ok
}

// stringSliceClaim extrae un claim de tipo array de strings, tolerante a que venga como
// []interface{} (lo normal al deserializar jwt.MapClaims) o como []string.
func stringSliceClaim(claims jwt.MapClaims, key string) []string {
	raw, ok := claims[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, it := range items {
		set[it] = struct{}{}
	}
	return set
}
