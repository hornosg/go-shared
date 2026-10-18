// Package receiver es el combinador del lado receptor del token de servicio (ACC-E09 T3, ADR-006
// «Alcance de tenant» y «Transición»), sin gin ni net/http: lo envuelven el middleware gin
// (middleware/s2sauth) y el adaptador net/http (s2stoken/s2shttp). No enlaza la carga de claves
// privadas: un receptor puro no puede firmar.
//
// Recibe los tres valores de transporte (X-Service-Token, Authorization, X-Tenant-ID) y aplica, en
// orden: S2S_DENY_SUB no parseable → firma/aud/exp/scope del token de servicio (s2stoken.Verify) →
// lista de denegación por sub verificado → tenant_scope permitido por la ruta (C-1) → regla de
// X-Tenant-ID. Los errores envuelven s2stoken.ErrUnauthenticated (401) o ErrForbidden (403); el
// adaptador responde sólo con StatusCode(err) y nunca con el texto (C-2).
package receiver

import (
	"os"

	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// SystemTenantMode dice qué hace la ruta con un token tenant_scope=system (C-1: un token system sólo
// vale en rutas marcadas como de sistema).
type SystemTenantMode int

const (
	// SystemDenied: la ruta no es de sistema; un token system → 403. Es el valor por defecto.
	SystemDenied SystemTenantMode = iota
	// SystemGlobal: operación de sistema que no es por tenant; un X-Tenant-ID presente → 403.
	SystemGlobal
	// SystemPerTenant: operación de sistema por tenant (lecturas del BFF, ADR-006): exige
	// X-Tenant-ID y lo acepta, siempre logueado con el sub.
	SystemPerTenant
)

// Config de una ruta (o grupo de rutas) receptora.
type Config struct {
	// Service es la verificación del token de servicio: keyring de iam, Audience de este receptor,
	// Namespace y los scopes que exige la ruta.
	Service s2stoken.Config
	// AllowUser habilita tenant_scope=user (llamada originada por un usuario, con su Bearer).
	AllowUser bool
	// System habilita tenant_scope=system en esta ruta y fija el trato de X-Tenant-ID.
	System SystemTenantMode
	// SystemOnlyScopes son scopes que sólo pueden venir con tenant_scope=system: un token user que
	// los trae → 403 (defensa en profundidad de C-1; iam ya prohíbe mezclar clases).
	SystemOnlyScopes []string
	// UserNamespace es el namespace esperado en el Bearer del usuario. Vacío → el de Service.
	UserNamespace string
	// DenySub es la lista S2S_DENY_SUB ya parseada (ParseDenySub).
	DenySub DenyList
	// Logger recibe s2s_tenant_mismatch, s2s_system_tenant y s2s_deny_sub como campos
	// estructurados (slog escapa los valores). Nunca recibe un token. nil → slog.Default().
	Logger *slog.Logger
}

// Result es lo que el adaptador deja en el contexto del request.
type Result struct {
	Service s2stoken.Principal
	// TenantID es el tenant efectivo: el del Bearer (user) o el del header en SystemPerTenant.
	TenantID string
	// UserClaims y Roles sólo existen en tenant_scope=user; en system quedan vacíos, así que un
	// RequireRole posterior falla cerrado.
	UserClaims jwt.MapClaims
	Roles      []string
}

// Namespace es el namespace efectivo del request: el del Bearer en tenant_scope=user (el combinador
// ya lo igualó al esperado) y el del token de servicio en system. Paridad con TenantValidation (N-4).
func (r Result) Namespace() string {
	if r.UserClaims != nil {
		ns, _ := r.UserClaims["namespace"].(string)
		return ns
	}
	return r.Service.Namespace
}

// Authenticate aplica el combinador sobre un request que trae X-Service-Token. serviceToken vacío
// es un error de programación del adaptador (sin header rige la credencial heredada) → 401.
func Authenticate(cfg Config, serviceToken, authorization, tenantHeader string) (Result, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	if strings.TrimSpace(serviceToken) == "" {
		return Result{}, unauthenticated("X-Service-Token ausente")
	}
	if cfg.DenySub.invalid {
		denySubRejections.Inc()
		log.Warn("s2s_deny_sub_invalid", "event", "s2s_deny_sub_invalid")
		return Result{}, unauthenticated("S2S_DENY_SUB no parseable: se rechaza todo token de servicio")
	}

	p, err := s2stoken.Verify(serviceToken, cfg.Service)
	if err != nil {
		return Result{}, err
	}
	if cfg.DenySub.Denies(p.Subject) {
		denySubRejections.Inc()
		log.Warn("s2s_deny_sub", "event", "s2s_deny_sub", "sub", p.Subject, "jti", p.ID)
		return Result{}, unauthenticated("emisor en S2S_DENY_SUB")
	}

	switch p.TenantScope {
	case s2stoken.TenantScopeSystem:
		return authenticateSystem(cfg, log, p, tenantHeader)
	case s2stoken.TenantScopeUser:
		return authenticateUser(cfg, log, p, authorization, tenantHeader)
	default:
		return Result{}, unauthenticated("tenant_scope no reconocido")
	}
}

// authenticateSystem: el Bearer se ignora para tenant y roles (nunca amplía lo que da el token).
func authenticateSystem(cfg Config, log *slog.Logger, p s2stoken.Principal, tenantHeader string) (Result, error) {
	switch cfg.System {
	case SystemGlobal:
		if tenantHeader != "" {
			return Result{}, forbidden("X-Tenant-ID en una operación de sistema que no es por tenant")
		}
		return Result{Service: p}, nil
	case SystemPerTenant:
		if tenantHeader == "" {
			return Result{}, forbidden("operación de sistema por tenant sin X-Tenant-ID")
		}
		u, uerr := uuid.Parse(tenantHeader)
		if uerr != nil || len(tenantHeader) != 36 {
			return Result{}, forbidden("X-Tenant-ID de una operación de sistema no es un UUID canónico")
		}
		tenantHeader = u.String()
		log.Info("s2s_system_tenant", "event", "s2s_system_tenant", "sub", p.Subject,
			"aud", p.Audience, "header_tenant_id", tenantHeader, "jti", p.ID)
		return Result{Service: p, TenantID: tenantHeader}, nil
	default:
		return Result{}, forbidden("token de sistema en una ruta que no es de sistema")
	}
}

func authenticateUser(cfg Config, log *slog.Logger, p s2stoken.Principal, authorization, tenantHeader string) (Result, error) {
	if !cfg.AllowUser {
		return Result{}, forbidden("token de usuario en una ruta sólo de sistema")
	}
	for _, s := range cfg.SystemOnlyScopes {
		if p.HasScope(s) {
			return Result{}, forbidden("scope de sistema con tenant_scope=user")
		}
	}
	bearer, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || strings.TrimSpace(bearer) == "" {
		return Result{}, unauthenticated("token user sin Bearer de usuario")
	}
	claims, err := VerifyUser(bearer, cfg.Service.Keyring)
	if err != nil {
		return Result{}, err
	}
	ns := cfg.UserNamespace
	if ns == "" {
		ns = cfg.Service.Namespace
	}
	if got, _ := claims["namespace"].(string); got != ns {
		return Result{}, forbidden("namespace del usuario ajeno")
	}
	tenant, _ := claims["tenant_id"].(string)
	if tenant == "" {
		// Con independencia de RejectMissingTenant del receptor (ADR-006).
		return Result{}, forbidden("Bearer de usuario sin tenant_id")
	}
	if tenantHeader != "" && tenantHeader != tenant {
		userID, _ := claims["user_id"].(string)
		log.Warn("s2s_tenant_mismatch", "event", "s2s_tenant_mismatch", "sub", p.Subject,
			"user_id", userID, "jwt_tenant_id", tenant, "header_tenant_id", tenantHeader, "jti", p.ID)
		return Result{}, forbidden("X-Tenant-ID distinto del tenant del usuario")
	}
	// X-Tenant-ID ausente con Bearer válido: se usa el tenant del Bearer (tabla de ADR-006). El
	// header nunca es la autoridad; el claim firmado por iam sí.
	return Result{Service: p, TenantID: tenant, UserClaims: claims, Roles: stringSlice(claims["roles"])}, nil
}

// VerifyUser verifica un Bearer de usuario: RS256 por kid contra el keyring de iam, exp obligatorio
// y el contrato de usuario (rechaza token_use=service, exige iss=iam-service).
func VerifyUser(bearer string, ring *jwtkeyring.Keyring) (jwt.MapClaims, error) {
	if ring == nil {
		return nil, unauthenticated("keyring ausente")
	}
	claims := jwt.MapClaims{}
	if err := s2stoken.ParseUser(bearer, claims, ring); err != nil {
		return nil, err
	}
	return claims, nil
}

// DenyList es S2S_DENY_SUB parseada. Un valor no parseable deja invalid=true: el receptor rechaza
// TODO token de servicio y mantiene el tráfico de usuarios (ADR-006 «Revocación» §3).
type DenyList struct {
	subs    map[string]struct{}
	invalid bool
}

var canonicalName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ParseDenySub parsea una lista de nombres canónicos separados por comas. Vacío → lista vacía. Ante
// un valor no parseable devuelve la lista en modo «rechazar todo» Y el error, para que el arranque lo
// loguee y lo exponga en métrica sin dejar de arrancar.
func ParseDenySub(raw string) (DenyList, error) {
	d := DenyList{subs: map[string]struct{}{}}
	if strings.TrimSpace(raw) == "" {
		return d, nil
	}
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if !canonicalName.MatchString(name) {
			d.invalid = true
			return d, errors.New("S2S_DENY_SUB no parseable: se rechaza todo token de servicio")
		}
		d.subs[name] = struct{}{}
	}
	return d, nil
}

// EnvDenySub es la variable de la lista de emisores denegados (ADR-006 «Revocación»).
const EnvDenySub = "S2S_DENY_SUB"

var (
	denySubInvalid = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "s2s_deny_sub_invalid",
		Help: "1 si S2S_DENY_SUB no es parseable y el receptor rechaza todo token de servicio (ADR-006).",
	})
	denySubRejections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "s2s_deny_sub_rejections_total",
		Help: "Tokens de servicio rechazados por S2S_DENY_SUB (emisor denegado o lista no parseable).",
	})
)

// DenyListFromEnv es el cableado recomendado de S2S_DENY_SUB (N-2 de la revisión de T3): lee la
// variable, registra en reg las métricas s2s_deny_sub_invalid (gauge, «en alto» ante un valor no
// parseable) y s2s_deny_sub_rejections_total, y loguea el error sin impedir el arranque. reg nil →
// prometheus.DefaultRegisterer; registrar dos veces en el mismo registro no es error. Una coma
// final o un nombre no canónico dejan la lista en «rechazar todo token de servicio» (falla cerrada,
// documentada en el CHANGELOG); el tráfico de usuarios y la credencial heredada siguen.
func DenyListFromEnv(reg prometheus.Registerer, log *slog.Logger) DenyList {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	if log == nil {
		log = slog.Default()
	}
	for _, c := range []prometheus.Collector{denySubInvalid, denySubRejections} {
		if err := reg.Register(c); err != nil {
			var already prometheus.AlreadyRegisteredError
			if !errors.As(err, &already) {
				log.Error("s2s_deny_sub_metric", "event", "s2s_deny_sub_metric", "error", err.Error())
			}
		}
	}
	d, err := ParseDenySub(os.Getenv(EnvDenySub))
	if err != nil {
		denySubInvalid.Set(1)
		log.Error("s2s_deny_sub_invalid", "event", "s2s_deny_sub_invalid", "error", err.Error())
	} else {
		denySubInvalid.Set(0)
	}
	return d
}

// Invalid informa si la lista quedó en modo «rechazar todo token de servicio».
func (d DenyList) Invalid() bool { return d.invalid }

// Denies informa si sub está denegado.
func (d DenyList) Denies(sub string) bool {
	if d.invalid {
		return true
	}
	_, ok := d.subs[sub]
	return ok
}

func stringSlice(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func unauthenticated(msg string) error { return fmt.Errorf("%w: %s", s2stoken.ErrUnauthenticated, msg) }
func forbidden(msg string) error       { return fmt.Errorf("%w: %s", s2stoken.ErrForbidden, msg) }
