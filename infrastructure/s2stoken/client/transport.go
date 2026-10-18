package client

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// Mode es el modo del emisor por destino (ADR-006 «Reversibilidad por servicio»): revertir un par es
// un cambio de configuración, no un redeploy.
type Mode string

const (
	// ModeLegacy: el emisor sigue mandando la credencial heredada del par. Default mientras el par no
	// se migró (T4–T7); T8 lo retira.
	ModeLegacy Mode = "legacy"
	// ModeToken: el emisor manda X-Service-Token (y el Bearer del usuario cuando la llamada es suya).
	ModeToken Mode = "token"
)

// ModeFor lee S2S_MODE_<DESTINO> (destino en mayúsculas, guiones → guión bajo). Ausente → legacy.
// Un valor no reconocido es un error: el emisor no arranca con un modo ambiguo.
func ModeFor(destination string) (Mode, error) {
	return parseMode(os.Getenv(ModeEnvVar(destination)))
}

// ModeEnvVar devuelve el nombre de la variable de modo para un destino (stock-service →
// S2S_MODE_STOCK_SERVICE).
func ModeEnvVar(destination string) string {
	return "S2S_MODE_" + strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(destination), "-", "_"))
}

func parseMode(raw string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(raw))) {
	case "", ModeLegacy:
		return ModeLegacy, nil
	case ModeToken:
		return ModeToken, nil
	default:
		return "", fmt.Errorf("s2s client: modo %q no reconocido (token|legacy)", raw)
	}
}

// Transport agrega X-Service-Token para (Audience, Scopes) a cada request. Ante un 401 del receptor pide
// una renovación al cliente (Refresh: single-flight y sin re-emitir un token recién emitido) y reintenta
// UNA sola vez, si el body se puede reenviar. No toca Authorization: el Bearer del usuario lo pone quien
// arma el request, en las llamadas que son de un usuario.
//
// Nunca adjunta el token a una request que es una redirección (req.Response != nil): un receptor que
// responde 302 hacia otro host no recibe la credencial (O-2 de la revisión L4 de T3).
type Transport struct {
	Base     http.RoundTripper
	Client   *Client
	Audience string
	Scopes   []string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response != nil {
		return t.base().RoundTrip(req) // redirección: sin credencial
	}
	token, err := t.Client.Token(req.Context(), t.Audience, t.Scopes...)
	if err != nil {
		return nil, err
	}
	resp, err := t.send(req, token)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	if req.Body != nil && req.GetBody == nil {
		return resp, nil
	}
	fresh, ok, rerr := t.Client.Refresh(req.Context(), token, t.Audience, t.Scopes...)
	if rerr != nil || !ok {
		return resp, nil // el 401 se entrega tal cual
	}
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		body, berr := req.GetBody()
		if berr != nil {
			return resp, nil
		}
		retry.Body = body
	}
	resp.Body.Close()
	return t.send(retry, fresh)
}

func (t *Transport) send(req *http.Request, token string) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set(s2stoken.HeaderServiceToken, token)
	return t.base().RoundTrip(out)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base == nil {
		return http.DefaultTransport
	}
	return t.Base
}
