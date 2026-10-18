// Package s2stoken es el núcleo del token de servicio S2S de la flota (ACC-E09 T3a, ADR-006): claims,
// constantes de contrato y el verificador. No depende de gin ni de net/http, como jwtkeyring, así que
// lo importan iam (emisor y receptor) y cualquier receptor sin arrastrar un framework.
//
// El token de servicio identifica y autoriza al SERVICIO emisor: no lleva tenant, usuario ni roles
// (eso viaja en el Bearer del usuario). Se firma con la misma clave privada de iam que los tokens de
// usuario y se verifica con el mismo keyring público; lo que lo separa de un token de usuario son los
// claims de contrato (iss, token_use, typ), que este paquete exige.
//
// Restricción permanente (ACC-E03 T6): sin rama HMAC ni parámetro de secreto compartido. La única
// Keyfunc es jwtkeyring.RS256Keyfunc.
package s2stoken

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
)

// Constantes de contrato (ADR-006 «Identificadores de contrato»). Son nombres de contrato,
// independientes del nombre del repo: sobreviven al rename de ACC-E07. Cambiarlas es una migración
// coordinada de iam y de toda la flota.
const (
	// Issuer es el iss del token de servicio; distinto del de los tokens de usuario.
	Issuer = "iam-service/s2s"
	// UserIssuer es el iss de los tokens de usuario. Los verificadores de usuario lo exigen
	// (T2/T3) y rechazan TokenUse.
	UserIssuer = "iam-service"
	// TokenUse es el valor del claim token_use de todo token de servicio.
	TokenUse = "service"
	// TokenType es el typ del header JOSE del token de servicio.
	TokenType = "s2s+jwt"
	// AssertionAudience es el aud de la aserción private_key_jwt que el emisor firma para pedir
	// el token a iam. Identificador canónico fijo, nunca una URL.
	AssertionAudience = "iam-service/s2s/token"
	// IAMAudience es el aud con el que iam/account se presenta como receptor de tokens de servicio.
	IAMAudience = "account-service"

	// TenantScopeUser: llamada originada por un usuario; el tenant sale del Bearer del usuario.
	TenantScopeUser = "user"
	// TenantScopeSystem: proceso sin usuario; sólo con los scopes de sistema que el registro enumera.
	TenantScopeSystem = "system"

	// TTL es la vida del token de servicio (exp = iat + TTL).
	TTL = 300 * time.Second
	// Leeway es la tolerancia de reloj del receptor sobre exp/iat/nbf.
	Leeway = 30 * time.Second
)

// Claims del token de servicio (ADR-006 «Claims»). aud es un string, no un array: un aud en array
// no decodifica y el token se rechaza (401). No hay tenant_id, act ni roles a propósito.
type Claims struct {
	Issuer      string           `json:"iss"`
	Subject     string           `json:"sub"`
	Audience    string           `json:"aud"`
	Scope       string           `json:"scope"`
	TokenUse    string           `json:"token_use"`
	TenantScope string           `json:"tenant_scope"`
	Namespace   string           `json:"namespace"`
	IssuedAt    *jwt.NumericDate `json:"iat,omitempty"`
	NotBefore   *jwt.NumericDate `json:"nbf,omitempty"`
	ExpiresAt   *jwt.NumericDate `json:"exp,omitempty"`
	ID          string           `json:"jti,omitempty"`
}

var _ jwt.Claims = (*Claims)(nil)

func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) { return c.ExpiresAt, nil }
func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error)       { return c.IssuedAt, nil }
func (c *Claims) GetNotBefore() (*jwt.NumericDate, error)      { return c.NotBefore, nil }
func (c *Claims) GetIssuer() (string, error)                   { return c.Issuer, nil }
func (c *Claims) GetSubject() (string, error)                  { return c.Subject, nil }
func (c *Claims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}

// Scopes devuelve el claim scope partido por espacios.
func (c *Claims) Scopes() []string { return strings.Fields(c.Scope) }

// Errores tipados: separan no autenticado (401) de prohibido (403). Todo error de Verify envuelve
// exactamente uno de los dos; StatusCode lo traduce sin que el adaptador tenga que mirar el texto.
var (
	ErrUnauthenticated = errors.New("s2s: token de servicio no autenticado")
	ErrForbidden       = errors.New("s2s: token de servicio sin permiso")
)

// StatusCode traduce un error de Verify a su código HTTP: 403 para ErrForbidden, 401 para todo lo
// demás (incluido un error desconocido: ante la duda, no autenticado). nil → 200.
func StatusCode(err error) int {
	switch {
	case err == nil:
		return 200
	case errors.Is(err, ErrForbidden):
		return 403
	default:
		return 401
	}
}

func unauthenticated(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, fmt.Sprintf(format, args...))
}

func forbidden(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrForbidden, fmt.Sprintf(format, args...))
}

// Config del receptor. Audience y Namespace son obligatorios: un receptor sin nombre propio o sin
// namespace esperado no puede decidir a quién está dirigido el token, así que rechaza todo.
type Config struct {
	// Keyring público de iam (el mismo de los tokens de usuario, ACC-E03). nil → rechaza todo.
	Keyring *jwtkeyring.Keyring
	// Audience es el nombre canónico de este receptor (stock-service, account-service…).
	Audience string
	// Namespace esperado del emisor (mc). Ajeno → 403.
	Namespace string
	// RequiredScopes que exige la ruta; todos deben estar en el token. Faltante → 403. Vacío es una
	// config inválida salvo que AnyScope sea true: por defecto se deniega (ADR-006, «la ruta exige su
	// scope»), para que una ruta sin scope declarado no quede abierta a todo emisor con este aud.
	RequiredScopes []string
	// AnyScope acepta cualquier scope (incluido ninguno) cuando RequiredScopes está vacío. Sólo para
	// rutas que se autorizan por otro medio y lo dejan escrito; nunca es el valor por defecto.
	AnyScope bool
	// Now permite fijar el reloj en tests. nil → time.Now.
	Now func() time.Time
}

// Validate chequea la config de arranque. Un receptor debería llamarlo al construirse y no arrancar
// si falla; Verify lo vuelve a aplicar y rechaza con 401 ante una config inválida (fail-closed).
func (cfg Config) Validate() error {
	if cfg.Keyring == nil {
		return errors.New("s2s: keyring ausente")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return errors.New("s2s: Audience del receptor vacío")
	}
	if strings.TrimSpace(cfg.Namespace) == "" {
		return errors.New("s2s: Namespace esperado vacío")
	}
	if cfg.Audience == AssertionAudience {
		return errors.New("s2s: Audience del receptor no puede ser el de la aserción de iam")
	}
	if len(cfg.RequiredScopes) == 0 && !cfg.AnyScope {
		return errors.New("s2s: RequiredScopes vacío (declarar el scope de la ruta o AnyScope)")
	}
	return nil
}

// Principal es el servicio emisor ya verificado.
type Principal struct {
	Subject     string
	Audience    string
	Scopes      []string
	TenantScope string
	Namespace   string
	ID          string
	KID         string
	ExpiresAt   time.Time
}

// HasScope informa si el token trae scope.
func (p Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsSystem informa si el token es de un proceso sin usuario (tenant_scope=system).
func (p Principal) IsSystem() bool { return p.TenantScope == TenantScopeSystem }

// Verify valida un token de servicio. Orden: config → firma RS256 por kid (keyring) e iss (dentro
// del parser) → typ → token_use → exp/iat/nbf (con Leeway) y vida ≤ TTL → aud → sub/jti/tenant_scope → (403) namespace
// → (403) scopes requeridos. Todo lo que dice «este token no es una credencial válida para mí» es
// 401; lo que dice «es válida pero no alcanza» es 403.
func Verify(tokenStr string, cfg Config) (Principal, error) {
	if err := cfg.Validate(); err != nil {
		return Principal{}, unauthenticated("config inválida: %v", err)
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}

	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithStrictDecoding(),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(Leeway),
		jwt.WithTimeFunc(now),
	)
	token, err := parser.ParseWithClaims(tokenStr, claims, jwtkeyring.RS256Keyfunc(cfg.Keyring))
	if err != nil {
		return Principal{}, unauthenticated("%v", err)
	}
	if typ, _ := token.Header["typ"].(string); typ != TokenType {
		return Principal{}, unauthenticated("typ %q, se espera %q", typ, TokenType)
	}
	if claims.TokenUse != TokenUse {
		return Principal{}, unauthenticated("token_use %q, se espera %q", claims.TokenUse, TokenUse)
	}
	if claims.IssuedAt == nil {
		return Principal{}, unauthenticated("iat ausente")
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt.Time) > TTL {
		return Principal{}, unauthenticated("vida del token mayor que %s", TTL)
	}
	if claims.Audience != cfg.Audience {
		return Principal{}, unauthenticated("aud %q no es este receptor (%q)", claims.Audience, cfg.Audience)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return Principal{}, unauthenticated("sub ausente")
	}
	if strings.TrimSpace(claims.ID) == "" {
		return Principal{}, unauthenticated("jti ausente")
	}
	if claims.TenantScope != TenantScopeUser && claims.TenantScope != TenantScopeSystem {
		return Principal{}, unauthenticated("tenant_scope %q no reconocido", claims.TenantScope)
	}

	if claims.Namespace != cfg.Namespace {
		return Principal{}, forbidden("namespace %q ajeno (se espera %q)", claims.Namespace, cfg.Namespace)
	}
	p := Principal{
		Subject:     claims.Subject,
		Audience:    claims.Audience,
		Scopes:      claims.Scopes(),
		TenantScope: claims.TenantScope,
		Namespace:   claims.Namespace,
		ID:          claims.ID,
		ExpiresAt:   claims.ExpiresAt.Time,
	}
	p.KID, _ = token.Header["kid"].(string)
	for _, required := range cfg.RequiredScopes {
		if !p.HasScope(required) {
			return Principal{}, forbidden("scope %q requerido", required)
		}
	}
	return p, nil
}
