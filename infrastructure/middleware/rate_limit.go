package middleware

import (
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/hornosg/go-shared/infrastructure/ratelimit"
)

// PlanTierFree es el tier por defecto cuando el JWT no trae el claim plan (token viejo) o
// no se puede leer. Coincide con la degradación fail-safe del emisor (ADR-003 D2).
const PlanTierFree = "FREE"

// LimitsProvider resuelve la regla de rate limiting para una celda (tier × feature).
// Cada servicio inyecta una implementación que cachea la matriz desde iam (ADR-003 D4).
// Devuelve ok=false cuando no hay límite configurado para esa celda → no se limita.
type LimitsProvider interface {
	RuleFor(tier, feature string) (ratelimit.Rule, bool)
}

// RateLimitConfig configura el middleware de rate limiting por tenant/plan (ADR-003).
type RateLimitConfig struct {
	Limiter  ratelimit.Limiter
	Provider LimitsProvider
	// Feature es el usecase costoso que protege este middleware (ej. "ai.bi_query").
	Feature string
	// KeyPrefix de la clave Redis (default "ratelimit").
	KeyPrefix string
	// FailClosed: si Redis no responde, rechazar (503) en vez de dejar pasar. Default
	// false = fail-open (QoS). true solo para ops destructivas/caras (ADR-003 D6).
	FailClosed bool
	// ObserveOnly: mide y emite headers/callback pero NO rechaza (rollout seguro, ADR-003
	// fase 3). Un exceso deja pasar el request y dispara OnLimitExceeded.
	ObserveOnly bool
	// OnBackendUnavailable se invoca cuando el backend (Redis) falla (para métricas/alerta).
	OnBackendUnavailable func(c *gin.Context, err error)
	// OnLimitExceeded se invoca cada vez que una request EXCEDE el límite (tanto en modo
	// enforce como observe-only) — para métricas (ratelimit_rejected_total).
	OnLimitExceeded func(c *gin.Context, feature string)
}

// RateLimit devuelve un middleware Gin que aplica el límite por (tenant, feature) según el
// plan del tenant. Debe correr DESPUÉS de TenantValidation (depende de tenant_id/jwt_claims
// en contexto). Emite headers RateLimit-* y responde 429 + Retry-After al exceder.
func RateLimit(cfg RateLimitConfig) gin.HandlerFunc {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit"
	}

	return func(c *gin.Context) {
		// Si falta cableado, no romper el request (defensivo).
		if cfg.Limiter == nil || cfg.Provider == nil || cfg.Feature == "" {
			c.Next()
			return
		}

		tenantID := c.GetString("tenant_id")
		if tenantID == "" {
			// Sin tenant no hay a quién atribuir el límite por plan; TenantValidation ya
			// decidió si dejar pasar. No se aplica límite por plan acá.
			c.Next()
			return
		}

		tier := PlanTierFromContext(c)
		rule, ok := cfg.Provider.RuleFor(tier, cfg.Feature)
		if !ok {
			// No hay límite configurado para esta celda → no se limita.
			c.Next()
			return
		}

		key := prefix + ":" + tenantID + ":" + cfg.Feature
		decision, err := cfg.Limiter.Allow(c.Request.Context(), key, rule)
		if err != nil {
			if cfg.OnBackendUnavailable != nil {
				cfg.OnBackendUnavailable(c, err)
			}
			if cfg.FailClosed {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "rate limiter unavailable"})
				return
			}
			// fail-open: dejar pasar (no degradar UX por un Redis caído).
			c.Next()
			return
		}

		setRateLimitHeaders(c, decision)
		if !decision.Allowed {
			if cfg.OnLimitExceeded != nil {
				cfg.OnLimitExceeded(c, cfg.Feature)
			}
			// Observe-only: medir y dejar pasar (rollout seguro, ADR-003 fase 3).
			if cfg.ObserveOnly {
				c.Next()
				return
			}
			retry := int(math.Ceil(decision.RetryAfter.Seconds()))
			if retry < 1 {
				retry = 1
			}
			c.Header("Retry-After", strconv.Itoa(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"feature": cfg.Feature,
			})
			return
		}
		c.Next()
	}
}

func setRateLimitHeaders(c *gin.Context, d ratelimit.Decision) {
	c.Header("RateLimit-Limit", strconv.Itoa(d.Limit))
	c.Header("RateLimit-Remaining", strconv.Itoa(d.Remaining))
	reset := int(math.Ceil(d.ResetAfter.Seconds()))
	if reset < 0 {
		reset = 0
	}
	c.Header("RateLimit-Reset", strconv.Itoa(reset))
}

// PlanTierFromContext lee el tier del plan del claim `plan` del JWT (lo deja
// TenantValidation en "jwt_claims"). Default FREE si no está (condición de arquitectura A1).
func PlanTierFromContext(c *gin.Context) string {
	claims, ok := claimsFromContext(c)
	if !ok {
		return PlanTierFree
	}
	plan, ok := claims["plan"].(map[string]interface{})
	if !ok {
		return PlanTierFree
	}
	tier, ok := plan["tier"].(string)
	if !ok || tier == "" {
		return PlanTierFree
	}
	return tier
}
