package s2stoken

import (
	"net/textproto"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
)

// Headers de transporte de ADR-006 «Transición»: la credencial se elige por header, nunca por iss.
const (
	// HeaderServiceToken lleva el token de servicio. Es el único header del que se lee.
	HeaderServiceToken = "X-Service-Token"
	// HeaderTenantID es el tenant declarado por el emisor; nunca es autoridad por sí solo.
	HeaderTenantID = "X-Tenant-ID"
)

// CheckUserClaims aplica el contrato de los tokens de USUARIO sobre claims ya verificados por firma
// (ACC-E09 T3, ADR-006): rechaza token_use=service y exige iss=UserIssuer. Lo comparten
// TenantValidation, VerifyPlatformJWT, el combinador S2S y los verificadores propios de webdata y
// catalog (T3b), para que un token de servicio presentado en Authorization nunca valga como usuario.
// Todo error es ErrUnauthenticated (401). El texto no incluye valores del token (C-2).
func CheckUserClaims(claims jwt.MapClaims) error {
	// Los tokens de usuario de iam no llevan token_use: cualquier valor no vacío (service u otro
	// desconocido) no es un token de usuario.
	if use, present := claims["token_use"]; present {
		if s, isString := use.(string); !isString || s != "" {
			return unauthenticated("token_use presente en un token de usuario")
		}
	}
	if iss, _ := claims["iss"].(string); iss != UserIssuer {
		return unauthenticated("iss de token de usuario inválido")
	}
	return nil
}

// ParseUser es el ÚNICO verificador de tokens de USUARIO para receptores que no usan los
// middlewares de go-shared (webdata, catalog — ACC-E09 T3b, nota N-1 de la revisión de T3): RS256
// por kid contra el keyring, exp obligatorio y CheckUserClaims. claims puede ser jwt.MapClaims o un
// struct propio del receptor; el contrato se aplica siempre sobre el payload completo, así que un
// struct que no declare token_use ni iss no lo saltea. No admite opciones del parser: con
// jwt.WithoutClaimsValidation un llamador anularía el exp obligatorio (C-1 de la revisión L4 de
// T3b), así que el leeway y las validaciones son fijos. El exp se vuelve a comprobar sobre el
// payload, no sobre lo que el struct del receptor diga de sí mismo. Todo error es
// ErrUnauthenticated (401) y su texto no incluye valores del token (C-2).
func ParseUser(tokenStr string, claims jwt.Claims, ring *jwtkeyring.Keyring) error {
	if ring == nil {
		return unauthenticated("keyring ausente")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(Leeway),
	)
	if _, err := parser.ParseWithClaims(tokenStr, claims, jwtkeyring.RS256Keyfunc(ring)); err != nil {
		return unauthenticated("token de usuario inválido")
	}
	mc, ok := claims.(jwt.MapClaims)
	if !ok {
		// La firma ya se verificó sobre este mismo string: decodificar el payload sin re-verificar
		// sólo sirve para aplicar el contrato sobre los claims que el struct no declara.
		mc = jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, mc); err != nil {
			return unauthenticated("token de usuario inválido")
		}
	}
	// exp sobre el payload: un struct propio podría mapear GetExpirationTime a otro campo.
	exp, ok := mc["exp"].(float64)
	if !ok || !time.Now().Before(time.Unix(int64(exp), 0).Add(Leeway)) {
		return unauthenticated("exp ausente o vencido en el payload")
	}
	return CheckUserClaims(mc)
}

// SingleHeader devuelve el único valor de name en h. Varios valores son ambiguos entre proxies
// (ACC-E09 T3b, H-4 de la revisión de T3): el receptor no elige uno y responde con error, así un
// Authorization o un X-Tenant-ID duplicado nunca decide la credencial ni el tenant. Ausente → "".
func SingleHeader(h map[string][]string, name string) (string, bool) {
	values := h[textproto.CanonicalMIMEHeaderKey(name)]
	switch len(values) {
	case 0:
		return "", true
	case 1:
		return values[0], true
	default:
		return "", false
	}
}

// sensitiveHeaders son los headers que nunca salen a un log: las dos credenciales del modelo de
// dos credenciales y las claves heredadas mientras dure el modo dual.
var sensitiveHeaders = []string{"Authorization", HeaderServiceToken, "X-Api-Key", "Cookie", "Proxy-Authorization"}

// RedactHeaders devuelve una copia de h (acepta un http.Header) con las credenciales reemplazadas
// por "[REDACTED]". Toda salida de headers de un middleware o cliente de la flota pasa por acá
// (ADR-006 «Logs»). Recibe el map crudo para que el núcleo no dependa de net/http.
func RedactHeaders(h map[string][]string) map[string][]string {
	sensitive := map[string]bool{}
	for _, name := range sensitiveHeaders {
		sensitive[textproto.CanonicalMIMEHeaderKey(name)] = true
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		if sensitive[textproto.CanonicalMIMEHeaderKey(k)] {
			out[k] = []string{"[REDACTED]"}
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}
