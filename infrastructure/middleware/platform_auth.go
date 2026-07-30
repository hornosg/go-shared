package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// PlatformAuthConfig configures VerifyPlatformJWT for platform-scoped routes —
// data that belongs to no tenant (the global catalog, marketplace and business
// types extracted into catalog-service, PLAT-E39).
type PlatformAuthConfig struct {
	JWTSecret string
	// Namespace is the expected project namespace in the JWT claim (e.g. "mc").
	// Empty disables namespace validation.
	Namespace string
}

// VerifyPlatformJWT verifies the HS256 JWT signature INSIDE the service and leaves the
// role available in the Gin context under the same keys go-shared uses (`jwt_claims`,
// `roles`), so it can be chained with RequireRole without any glue.
//
// Unlike TenantValidation, this middleware does NOT require or validate `X-Tenant-ID`:
// platform data has no tenant, so coupling the authorization gate to a tenant_id makes
// no sense for these routes. It follows the same pattern iam-service already uses for
// its cross-tenant routes (`adminGroup`): verified JWT + `roles` claim, no tenant coupling.
//
// Fail-closed by design (PLAT-E39 D3.1/D3.2): without a valid token → 401. The role is
// derived EXCLUSIVELY from the `roles` claim of the already-verified JWT — never from a
// header carrying the raw role injected by the client or by Kong, which stays forgeable
// while PLAT-E37 (stripping those headers at the edge) does not exist. This middleware
// only reads the `Authorization` header.
//
// It lives in go-shared because three services (catalog-service today; webdata-service and
// commerce-ai-service in PLAT-E39 T9/T10) need exactly this token-verified role gate. That
// duplication — the raw `X-User-Role` hole implemented once per service — is what PLAT-E39
// exists to close, so the control lives in the shared kernel, written once.
func VerifyPlatformJWT(cfg PlatformAuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		// WithExpirationRequired: jwt/v5 valida `exp` SÓLO si el claim está presente, así que un
		// token emitido sin `exp` no caduca nunca. Para un middleware normal eso sería una
		// debilidad; para éste es crítico, porque es el control ÚNICO de acceso a las 14 tablas
		// de plataforma: no llevan `tenant_id`, así que no hay RLS que sirva de red debajo
		// (PLAT-E39 D3.2). Un token `system_admin` sin `exp` sería una llave maestra permanente
		// sobre todo el catálogo. Exigir la presencia del claim es una línea; detectar la fuga de
		// un token eterno, no. Condición vinculante del gate L4 (@dev-security, 2026-07-28).
		_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWTSecret), nil
		}, jwt.WithExpirationRequired())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		if cfg.Namespace != "" {
			if ns, _ := claims["namespace"].(string); ns != cfg.Namespace {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Namespace mismatch: token does not belong to this project",
				})
				return
			}
		}

		c.Set("jwt_claims", claims)
		c.Set("roles", stringSliceClaim(claims, "roles"))
		c.Next()
	}
}
