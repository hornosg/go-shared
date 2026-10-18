package s2sauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hornosg/go-shared/infrastructure/middleware/s2sauth"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
)

// H-4 (revisión de T3): un Authorization o un X-Tenant-ID repetido es ambiguo entre proxies; el
// combinador no elige uno.
func TestRechaza_HeadersRepetidos(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	svc := h.svc(t, "user", "stock:read")
	bearer := h.user(t, "T1")
	cases := []struct {
		name   string
		header string
		values []string
		code   int
	}{
		{"authorization repetido", "Authorization", []string{bearer, bearer}, http.StatusUnauthorized},
		{"x-tenant-id repetido", s2stoken.HeaderTenantID, []string{"T1", "T2"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/r", nil)
			req.Header.Set(s2stoken.HeaderServiceToken, svc)
			req.Header.Set("Authorization", bearer)
			req.Header.Del(tc.header)
			for _, v := range tc.values {
				req.Header.Add(tc.header, v)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			want(t, w, tc.code)
		})
	}
	// Control: con un solo valor de cada uno el mismo request pasa.
	want(t, do(r, map[string]string{s2stoken.HeaderServiceToken: svc, "Authorization": bearer, s2stoken.HeaderTenantID: "T1"}), http.StatusOK)
}

// N-4: paridad de namespace con TenantValidation, en user (del Bearer) y en system (del token).
func TestNamespaceEnElContexto(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		name, scope string
		mode        receiver.SystemTenantMode
		bearer      bool
	}{
		{"user", "user", receiver.SystemDenied, true},
		{"system", "system", receiver.SystemGlobal, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			var got any
			r.GET("/r", s2sauth.Middleware(h.cfg(tc.mode, ""), nil), func(c *gin.Context) {
				got, _ = c.Get("namespace")
				c.Status(http.StatusOK)
			})
			headers := map[string]string{s2stoken.HeaderServiceToken: h.svc(t, tc.scope, "stock:read")}
			if tc.bearer {
				headers["Authorization"] = h.user(t, "T1")
			}
			want(t, do(r, headers), http.StatusOK)
			if got != "mc" {
				t.Fatalf("namespace en el contexto = %v, se espera mc", got)
			}
		})
	}
}
