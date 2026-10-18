package s2sauth_test

// Tests de contrato del adaptador gin escritos en la fase TEST (ACC-E09 T3) desde el Contrato de la
// épica: «el combinador decide por la presencia de X-Service-Token» y el token de sistema no
// trae roles, así que un RequireRole posterior falla cerrado.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hornosg/go-shared/infrastructure/middleware"
	"github.com/hornosg/go-shared/infrastructure/middleware/s2sauth"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
)

// Un X-Service-Token presente pero vacío es un token de servicio inválido: el combinador decide por
// la PRESENCIA del header, así que no debe caer a la credencial heredada.
func TestXServiceTokenPresenteVacio_NoCaeALaHeredada(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	req.Header["X-Service-Token"] = []string{""}
	req.Header.Set("X-Legacy-Key", "ok")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || h.legacyCalls != 0 {
		t.Fatalf("X-Service-Token vacío: status %d, heredada consultada %d veces; se espera 401 sin heredada", w.Code, h.legacyCalls)
	}
}

// RequireRole después del combinador: con token user los roles salen del Bearer (control positivo);
// con token system el Bearer se ignora y RequireRole debe dar 403 aunque el Bearer sea de admin.
func TestRequireRole_TokenSystemNoUsaRolesDelBearer(t *testing.T) {
	h := newHarness(t)
	route := func(mode receiver.SystemTenantMode) *gin.Engine {
		r := gin.New()
		r.GET("/r", s2sauth.Middleware(h.cfg(mode, ""), nil), middleware.RequireRole("admin"), func(c *gin.Context) { c.Status(200) })
		return r
	}
	admin := h.user(t, "T1") // roles: admin
	want(t, do(route(receiver.SystemDenied), map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": admin}), 200)
	want(t, do(route(receiver.SystemGlobal), map[string]string{"X-Service-Token": h.svc(t, "system", "stock:read"), "Authorization": admin}), 403)
	want(t, do(route(receiver.SystemPerTenant), map[string]string{"X-Service-Token": h.svc(t, "system", "stock:read"), "Authorization": admin, "X-Tenant-ID": "11111111-1111-1111-1111-111111111119"}), 403)
}

// Sin X-Service-Token, un request que sólo trae X-Tenant-ID no se autentica por el combinador: el
// header nunca es la autoridad del tenant.
func TestSoloXTenantID_NoAutentica(t *testing.T) {
	h := newHarness(t)
	want(t, do(h.router(h.cfg(receiver.SystemPerTenant, ""), nil), map[string]string{"X-Tenant-ID": "T1"}), 401)
	if h.legacyCalls != 1 {
		t.Fatalf("sin X-Service-Token debe decidir la heredada (llamadas: %d)", h.legacyCalls)
	}
}

// H-1/N-3: un X-Tenant-ID que no es UUID en una operación de sistema por tenant → 403 (lo da el combinador,
// no RequireRole), y el mismo request con un UUID válido sí llega al handler.
func TestSystemPerTenant_TenantNoUUIDEs403(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemPerTenant, ""), nil)
	tok := h.svc(t, "system", "stock:read")
	want(t, do(r, map[string]string{"X-Service-Token": tok, "X-Tenant-ID": "T1"}), 403)
	want(t, do(r, map[string]string{"X-Service-Token": tok, "X-Tenant-ID": "11111111-1111-1111-1111-111111111119"}), 200)
}

// H-4: X-Service-Token repetido es ambiguo entre proxies → 401, nunca la heredada.
func TestXServiceTokenRepetido_401SinHeredada(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	req.Header.Add("X-Service-Token", h.svc(t, "user", "stock:read"))
	req.Header.Add("X-Service-Token", h.svc(t, "user", "stock:read"))
	req.Header.Set("Authorization", h.user(t, "T1"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	want(t, w, 401)
	if h.legacyCalls != 0 {
		t.Fatalf("un header repetido no puede caer a la heredada (llamadas: %d)", h.legacyCalls)
	}
}
