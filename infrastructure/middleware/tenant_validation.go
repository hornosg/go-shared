package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TenantMismatchHandler is called when the X-Tenant-ID header does not match the JWT tenant_id claim.
type TenantMismatchHandler func(userID, jwtTenantID, headerTenantID, ipAddress string)

// NamespaceMismatchHandler is called when the JWT namespace claim does not match the expected namespace.
type NamespaceMismatchHandler func(userID, jwtNamespace, expectedNamespace, ipAddress string)

// TenantValidationConfig holds configuration for the TenantValidation middleware.
type TenantValidationConfig struct {
	JWTSecret string
	// Namespace is the expected project namespace (e.g. "mc" for mercado-cercano).
	// When set, the JWT must carry a matching "namespace" claim.
	// When empty, namespace validation is skipped — backwards-compatible behaviour.
	Namespace           string
	ExcludedRoutes      []string
	OnTenantMismatch    TenantMismatchHandler
	OnNamespaceMismatch NamespaceMismatchHandler
	// RejectMissingTenant cierra el bypass histórico (IDOR cross-tenant): cuando es true,
	// un token SIN claim tenant_id se rechaza con 403 en vez de dejarlo pasar sin validar.
	//
	// Default false PRESERVA el comportamiento histórico para no romper en bloque a los 13
	// servicios de la flota (algunos emisores S2S aún firman tokens sin tenant_id). Se debe
	// activar EXPLÍCITAMENTE por servicio una vez verificado que ningún flujo legítimo
	// depende del bypass. OBLIGATORIO en servicios que manejan dinero (caja/sales): un
	// endpoint de caja NO puede exponerse con este flag en false.
	//
	// DEUDA DE ROLLOUT: el objetivo final es invertir este default a fail-closed una vez
	// migrados todos los emisores S2S. Ver ADR/memoria del cierre de bypass de tenant.
	RejectMissingTenant bool
}

// TenantValidation returns a Gin middleware that:
//  1. Validates the "namespace" claim in the JWT matches cfg.Namespace (when configured).
//  2. Validates the X-Tenant-ID request header matches the "tenant_id" claim in the JWT.
func TenantValidation(cfg TenantValidationConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isExcluded(c.Request.URL.Path, cfg.ExcludedRoutes) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			return
		}

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		if cfg.Namespace != "" {
			jwtNamespace, _ := claims["namespace"].(string)
			if jwtNamespace != cfg.Namespace {
				if cfg.OnNamespaceMismatch != nil {
					userID, _ := claims["user_id"].(string)
					cfg.OnNamespaceMismatch(userID, jwtNamespace, cfg.Namespace, c.ClientIP())
				}
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Namespace mismatch: token does not belong to this project",
				})
				return
			}
		}

		jwtTenantID, ok := claims["tenant_id"].(string)
		if !ok || jwtTenantID == "" {
			if cfg.RejectMissingTenant {
				if cfg.OnTenantMismatch != nil {
					userID, _ := claims["user_id"].(string)
					cfg.OnTenantMismatch(userID, "", c.GetHeader("X-Tenant-ID"), c.ClientIP())
				}
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Forbidden: token is missing tenant_id claim",
				})
				return
			}
			// Bypass histórico (default): pasa sin validar tenant. No setea jwt_claims/roles,
			// por lo que RequireRole downstream falla-cerrado correctamente.
			c.Next()
			return
		}

		headerTenantID := c.GetHeader("X-Tenant-ID")
		if headerTenantID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
			return
		}

		if jwtTenantID != headerTenantID {
			if cfg.OnTenantMismatch != nil {
				userID, _ := claims["user_id"].(string)
				cfg.OnTenantMismatch(userID, jwtTenantID, headerTenantID, c.ClientIP())
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Tenant mismatch: X-Tenant-ID does not match token tenant",
			})
			return
		}

		c.Set("tenant_id", jwtTenantID)
		c.Set("jwt_claims", claims)
		c.Set("roles", stringSliceClaim(claims, "roles"))
		c.Next()
	}
}

func isExcluded(path string, excludedRoutes []string) bool {
	for _, route := range excludedRoutes {
		if strings.HasSuffix(route, "*") {
			prefix := strings.TrimSuffix(route, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if path == route {
			return true
		}
	}
	return false
}
