// Package s2shttp es el adaptador net/http del combinador S2S (ACC-E09 T3) para receptores sin gin
// (webdata usa chi). Mismo contrato que middleware/s2sauth: la credencial se elige por la presencia
// de X-Service-Token, un token inválido da 401 sin caer a la heredada y la respuesta de error es
// genérica (C-2).
package s2shttp

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
)

type ctxKey struct{}

// Middleware devuelve el combinador. legacy envuelve el handler con la credencial heredada que el
// receptor valida hoy; nil → sin X-Service-Token se responde 401.
func Middleware(cfg receiver.Config, legacy func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if err := cfg.Service.Validate(); err != nil {
		panic("s2shttp: " + err.Error())
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		var legacyHandler http.Handler
		if legacy != nil {
			legacyHandler = legacy(next)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Presencia del header, no valor (ver s2sauth): vacío o repetido → 401, nunca la heredada.
			values, present := r.Header[http.CanonicalHeaderKey(s2stoken.HeaderServiceToken)]
			if present && len(values) != 1 {
				writeError(w, s2stoken.ErrUnauthenticated)
				return
			}
			serviceToken := ""
			if present {
				serviceToken = values[0]
			}
			if !present {
				log.Debug("s2s_auth", "s2s_auth", "legacy_key", "path", r.URL.Path)
				if legacyHandler == nil {
					writeError(w, s2stoken.ErrUnauthenticated)
					return
				}
				legacyHandler.ServeHTTP(w, r)
				return
			}
			res, err := receiver.Authenticate(cfg, serviceToken, r.Header.Get("Authorization"), r.Header.Get(s2stoken.HeaderTenantID))
			if err != nil {
				log.Warn("s2s_auth_rejected", "event", "s2s_auth_rejected", "s2s_auth", "token",
					"status", s2stoken.StatusCode(err), "reason", err.Error(), "path", r.URL.Path)
				writeError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, res)))
		})
	}
}

// FromContext devuelve el resultado del combinador, si el request entró con token de servicio.
func FromContext(ctx context.Context) (receiver.Result, bool) {
	res, ok := ctx.Value(ctxKey{}).(receiver.Result)
	return res, ok
}

func writeError(w http.ResponseWriter, err error) {
	code := s2stoken.StatusCode(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + http.StatusText(code) + `"}`))
}
