// Package s2sauth es el adaptador gin del combinador S2S (ACC-E09 T3, ADR-006 «Transición»).
//
// La credencial se elige por header: si llega X-Service-Token se aplica receiver.Authenticate y un
// token inválido responde 401 SIN caer a la credencial heredada; sin X-Service-Token rige la heredada
// (el middleware que el receptor ya usa hoy: TenantValidation, su API key dedicada…). Cada request
// queda logueado con s2s_auth=token|legacy_key. La respuesta de error es genérica (C-2): sólo el
// código de s2stoken.StatusCode, nunca el texto del error.
package s2sauth

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
)

// Claves del contexto gin. tenant_id, jwt_claims y roles son las mismas que deja TenantValidation,
// para que RequireRole y los handlers existentes funcionen sin pegamento.
const (
	ContextPrincipal = "s2s_principal"
	ContextAuth      = "s2s_auth"
)

// Middleware devuelve el combinador. legacy es la credencial heredada que el receptor valida hoy;
// nil → sin X-Service-Token se responde 401 (receptor ya migrado).
func Middleware(cfg receiver.Config, legacy gin.HandlerFunc) gin.HandlerFunc {
	if err := cfg.Service.Validate(); err != nil {
		panic("s2sauth: " + err.Error())
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return func(c *gin.Context) {
		// Se decide por PRESENCIA del header (ADR-006): uno presente pero vacío no baja en silencio a la
		// credencial heredada (ocultaría una migración rota), y varios valores son ambiguos entre proxies.
		values, present := c.Request.Header[http.CanonicalHeaderKey(s2stoken.HeaderServiceToken)]
		if present && len(values) != 1 {
			abort(c, s2stoken.ErrUnauthenticated)
			return
		}
		serviceToken := ""
		if present {
			serviceToken = values[0]
		}
		if !present {
			c.Set(ContextAuth, "legacy_key")
			log.Debug("s2s_auth", "s2s_auth", "legacy_key", "path", c.FullPath())
			if legacy == nil {
				abort(c, s2stoken.ErrUnauthenticated)
				return
			}
			legacy(c)
			return
		}

		authorization, okAuth := s2stoken.SingleHeader(c.Request.Header, "Authorization")
		tenantHeader, okTenant := s2stoken.SingleHeader(c.Request.Header, s2stoken.HeaderTenantID)
		if !okAuth {
			abort(c, s2stoken.ErrUnauthenticated)
			return
		}
		if !okTenant {
			abort(c, s2stoken.ErrForbidden)
			return
		}
		res, err := receiver.Authenticate(cfg, serviceToken, authorization, tenantHeader)
		if err != nil {
			log.Warn("s2s_auth_rejected", "event", "s2s_auth_rejected", "s2s_auth", "token",
				"status", s2stoken.StatusCode(err), "reason", err.Error(), "path", c.FullPath())
			abort(c, err)
			return
		}
		c.Set(ContextAuth, "token")
		c.Set(ContextPrincipal, res.Service)
		if res.TenantID != "" {
			c.Set("tenant_id", res.TenantID)
		}
		if res.UserClaims != nil {
			c.Set("jwt_claims", res.UserClaims)
			c.Set("roles", res.Roles)
		}
		// Paridad con TenantValidation (N-4): los handlers que leen "namespace" ven el del usuario
		// en tenant_scope=user (ya igualado al esperado por el combinador) y el del token en system.
		if ns := res.Namespace(); ns != "" {
			c.Set("namespace", ns)
		}
		log.Debug("s2s_auth", "s2s_auth", "token", "sub", res.Service.Subject, "path", c.FullPath())
		c.Next()
	}
}

// PrincipalFromContext devuelve el servicio emisor verificado, si el request entró con token.
func PrincipalFromContext(c *gin.Context) (s2stoken.Principal, bool) {
	v, ok := c.Get(ContextPrincipal)
	if !ok {
		return s2stoken.Principal{}, false
	}
	p, ok := v.(s2stoken.Principal)
	return p, ok
}

func abort(c *gin.Context, err error) {
	code := s2stoken.StatusCode(err)
	c.AbortWithStatusJSON(code, gin.H{"error": http.StatusText(code)})
}
