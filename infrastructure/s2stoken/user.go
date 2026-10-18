package s2stoken

import (
	"net/textproto"

	"github.com/golang-jwt/jwt/v5"
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
