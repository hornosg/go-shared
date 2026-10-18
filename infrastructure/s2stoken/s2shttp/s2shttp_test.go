package s2shttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2shttp"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2stest"
)

func TestAdaptadorNetHTTP(t *testing.T) {
	iam := s2stest.NewIAM(t)
	cfg := receiver.Config{
		Service: s2stoken.Config{Keyring: iam.Keyring, Audience: "catalog-service", Namespace: "mc", RequiredScopes: []string{"global-product:write"}},
		System:  receiver.SystemGlobal,
	}
	legacyCalls := 0
	legacy := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			legacyCalls++
			if r.Header.Get("X-Legacy-Key") != "ok" {
				w.WriteHeader(401)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	h := s2shttp.Middleware(cfg, legacy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if res, ok := s2shttp.FromContext(r.Context()); ok && res.Service.Subject != "webdata" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	run := func(hdr map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	ok := iam.SignService(t, s2stest.ServiceClaims("webdata", "catalog-service", "system", "global-product:write"))
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"token system válido", map[string]string{"X-Service-Token": ok}, 200},
		{"heredada sin token", map[string]string{"X-Legacy-Key": "ok"}, 200},
		{"token inválido no cae a la heredada", map[string]string{"X-Service-Token": "x", "X-Legacy-Key": "ok"}, 401},
		{"scope insuficiente", map[string]string{"X-Service-Token": iam.SignService(t, s2stest.ServiceClaims("webdata", "catalog-service", "system", "other"))}, 403},
		{"aud ajeno", map[string]string{"X-Service-Token": iam.SignService(t, s2stest.ServiceClaims("webdata", "pim-service", "system", "global-product:write"))}, 401},
		{"system con X-Tenant-ID en ruta global", map[string]string{"X-Service-Token": ok, "X-Tenant-ID": "T1"}, 403},
		{"token user sin Bearer", map[string]string{"X-Service-Token": iam.SignService(t, s2stest.ServiceClaims("webdata", "catalog-service", "user", "global-product:write"))}, 403},
	}
	for _, tc := range cases {
		if got := run(tc.hdr); got != tc.want {
			t.Errorf("%s: %d, se espera %d", tc.name, got, tc.want)
		}
	}
	if legacyCalls != 1 {
		t.Fatalf("la heredada se consultó %d veces, se espera 1", legacyCalls)
	}
}
