package s2shttp_test

// Test de contrato escrito en la fase TEST (ACC-E09 T3): el combinador decide por la PRESENCIA de
// X-Service-Token; presente pero vacío es un token inválido y no cae a la credencial heredada.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2shttp"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2stest"
)

func TestXServiceTokenPresenteVacio_NoCaeALaHeredada(t *testing.T) {
	iam := s2stest.NewIAM(t)
	cfg := receiver.Config{
		Service: s2stoken.Config{Keyring: iam.Keyring, Audience: "catalog-service", Namespace: "mc", RequiredScopes: []string{"global-product:write"}},
		System:  receiver.SystemGlobal,
	}
	legacyCalls := 0
	legacy := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			legacyCalls++
			next.ServeHTTP(w, r)
		})
	}
	h := s2shttp.Middleware(cfg, legacy)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header["X-Service-Token"] = []string{""}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || legacyCalls != 0 {
		t.Fatalf("X-Service-Token vacío: status %d, heredada consultada %d veces; se espera 401 sin heredada", w.Code, legacyCalls)
	}
}
